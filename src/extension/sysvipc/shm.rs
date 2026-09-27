//! Shared memory — port of extension/sysvipc/sysvipc_shm.c.
//!
//! Each SysV shm segment is backed by an anonymous file owned by a
//! detached helper process (`--shm-helper`); `shmat` transfers the fd
//! into the tracee through a Unix SEQPACKET socket via SCM_RIGHTS, then
//! the tracee `mmap`s it — all as chained syscalls.

use std::cell::RefCell;
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

use super::*;
use crate::arch::SYSCALL_AVOIDER;
use crate::syscall::chain::{force_chain_final_result, register_chained_syscall};
use crate::sysnum::detranslate_sysnum;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{
    get_abi, is_32on64_mode, peek_reg, poke_reg, set_sysnum, Reg, RegVersion,
};
use crate::tracee::Tracee;
use crate::Word;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;

const SOCK_SEQPACKET: i32 = 5;
const SCM_RIGHTS: i32 = 1;

const SHMHELPER_SOCKET_LEN: usize = 108;

#[derive(Clone, Copy, PartialEq)]
#[repr(i32)]
enum HelperOp {
    Distribute = 0,
    Alloc = 1,
    Free = 2,
    LibandroidShmget = 3,
    LibandroidShmat = 4,
    LibandroidShmdt = 5,
    LibandroidShmctlRmid = 6,
    LibandroidShmctlStat = 7,
}

/// `SysVIpcShmHelperRequest` — wire format with the helper.
#[repr(C)]
struct HelperRequest {
    op: i32,
    fd: i32,
    size: usize,
    key: Word,
}

// `sysvipc_shm_helper_addr` — the socket path the helper printed.
thread_local! {
    static HELPER: RefCell<Option<HelperConn>> = const { RefCell::new(None) };
}

struct HelperConn {
    proot2helper: std::fs::File,
    helper2proot: std::fs::File,
    addr: [u8; SHMHELPER_SOCKET_LEN],
}

/// `sysvipc_shm_send_helper_request()` — launch the helper on first use,
/// then write the request and read back `response_size` bytes.
fn send_helper_request(request: &HelperRequest, response: &mut [u8]) {
    HELPER.with(|h| {
        if h.borrow().is_none() {
            *h.borrow_mut() = launch_helper();
        }
        let mut hb = h.borrow_mut();
        let Some(conn) = hb.as_mut() else {
            return;
        };
        let req_bytes = unsafe {
            std::slice::from_raw_parts(
                request as *const HelperRequest as *const u8,
                std::mem::size_of::<HelperRequest>(),
            )
        };
        let _ = conn.proot2helper.write_all(req_bytes);
        let mut off = 0;
        while off < response.len() {
            match conn.helper2proot.read(&mut response[off..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => off += n,
            }
        }
    });
}

/// Launch `proot --shm-helper` detached via double-fork; the socket path
/// arrives on its stdout pipe.
fn launch_helper() -> Option<HelperConn> {
    unsafe {
        let mut p2h = [0i32; 2];
        let mut h2p = [0i32; 2];
        if libc::pipe2(p2h.as_mut_ptr(), libc::O_CLOEXEC) < 0 {
            return None;
        }
        if libc::pipe2(h2p.as_mut_ptr(), libc::O_CLOEXEC) < 0 {
            libc::close(p2h[0]);
            libc::close(p2h[1]);
            return None;
        }
        let forked = libc::fork();
        if forked == 0 {
            libc::close(p2h[1]);
            libc::close(h2p[0]);
            libc::dup2(p2h[0], 0);
            libc::dup2(h2p[1], 1);
            libc::close(p2h[0]);
            libc::close(h2p[1]);
            libc::fcntl(0, libc::F_SETFL, 0);
            libc::fcntl(1, libc::F_SETFL, 0);
            // Fork again to detach from proot's waitpid().
            let forked2 = libc::fork();
            if forked2 == 0 {
                let exe = CString::new("/proc/self/exe").unwrap();
                let arg0 = CString::new("proot").unwrap();
                let arg1 = CString::new("--shm-helper").unwrap();
                libc::execl(
                    exe.as_ptr(),
                    arg0.as_ptr(),
                    arg1.as_ptr(),
                    std::ptr::null::<u8>(),
                );
                libc::_exit(1);
            }
            libc::_exit(0);
        } else if forked < 0 {
            libc::close(p2h[0]);
            libc::close(p2h[1]);
            libc::close(h2p[0]);
            libc::close(h2p[1]);
            return None;
        }
        libc::close(p2h[0]);
        libc::close(h2p[1]);
        let mut addr = [0u8; SHMHELPER_SOCKET_LEN];
        let nread = libc::read(h2p[0], addr.as_mut_ptr() as *mut _, SHMHELPER_SOCKET_LEN);
        if nread as usize != SHMHELPER_SOCKET_LEN {
            libc::close(p2h[1]);
            libc::close(h2p[0]);
            return None;
        }
        Some(HelperConn {
            proot2helper: std::fs::File::from_raw_fd(p2h[1]),
            helper2proot: std::fs::File::from_raw_fd(h2p[0]),
            addr,
        })
    }
}

/// `sysvipc_shm_recvmsg_pointers()` — lay out an msghdr+iovec+cmsghdr in
/// `guest_buf` so a recvmsg can receive an SCM_RIGHTS fd.
struct RecvmsgPointers {
    msghdr_ptr: Word,
    cmsg_controllen_ptr: Word,
    cmsg_control_ptr: Word,
}

fn recvmsg_pointers(
    tracee: &mut Tracee,
    guest_buf: Word,
    do_write: bool,
) -> Result<RecvmsgPointers, i32> {
    let sockaddr_un_len = std::mem::size_of::<libc::sockaddr_un>() as Word;
    #[cfg(target_arch = "x86_64")]
    let is32 = is_32on64_mode(tracee);
    #[cfg(not(target_arch = "x86_64"))]
    let is32 = true;

    let ptr_len: Word = if is32 { 4 } else { 8 };
    let buf_end = guest_buf + sockaddr_un_len;
    let data_addr = buf_end - 4;
    let data_iov_length = data_addr - ptr_len;
    let data_iov_addr = data_iov_length - ptr_len;
    let msghdr_flags = data_iov_addr - ptr_len;
    let msghdr_controllen = msghdr_flags - ptr_len;
    let msghdr_control = msghdr_controllen - ptr_len;
    let msghdr_iovlen = msghdr_control - ptr_len;
    let msghdr_iov = msghdr_iovlen - ptr_len;
    let msghdr = msghdr_iov - ptr_len * 2; // name & namelen unused
                                           // control data is at guest_buf

    if do_write {
        let mut data = vec![0u8; sockaddr_un_len as usize];
        let mut put = |off: Word, v: u64| {
            let o = (off - guest_buf) as usize;
            if is32 {
                data[o..o + 4].copy_from_slice(&(v as u32).to_ne_bytes());
            } else {
                data[o..o + 8].copy_from_slice(&v.to_ne_bytes());
            }
        };
        put(data_iov_addr, data_addr);
        put(data_iov_length, 1);
        put(msghdr_iov, data_iov_addr);
        put(msghdr_iovlen, 1);
        put(msghdr_control, guest_buf);
        put(msghdr_controllen, 20); // sizeof(cmsghdr) + sizeof(uint64_t)
        let status = write_data(tracee, guest_buf, &data);
        if status < 0 {
            return Err(status);
        }
    }

    Ok(RecvmsgPointers {
        msghdr_ptr: msghdr,
        cmsg_controllen_ptr: msghdr_controllen,
        cmsg_control_ptr: guest_buf,
    })
}

pub fn shmget(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let shm_key = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
    let shm_size = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as usize;
    let shmflg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i32;

    // WITH_LIBANDROID_SHMEM is not enabled on Linux builds.
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let mut nsb = ns.borrow_mut();
    let shms = &mut nsb.shms;

    let mut unused_slot = 0usize;
    let mut found_unused_slot = false;
    let mut found_shm = false;
    let mut shm_index = 0usize;
    for (i, s) in shms.iter().enumerate() {
        if s.valid {
            if shm_key != IPC_PRIVATE && s.key == shm_key {
                shm_index = i;
                found_shm = true;
                break;
            }
        } else if !found_unused_slot {
            unused_slot = i;
            found_unused_slot = true;
        }
    }

    if !found_shm {
        if (shmflg & IPC_CREAT) == 0 {
            return -libc::ENOENT;
        }
        let idx = if found_unused_slot {
            unused_slot
        } else {
            shms.push(SharedMem::default());
            shms.len() - 1
        };
        shm_index = idx;
        let generation = shms[idx].generation;
        let request = HelperRequest {
            op: HelperOp::Alloc as i32,
            fd: ipc_object_id(shm_index, generation),
            size: shm_size,
            key: 0,
        };
        let mut fd_bytes = (-libc::EIO).to_ne_bytes();
        send_helper_request(&request, &mut fd_bytes);
        let fd = i32::from_ne_bytes(fd_bytes);
        if fd < 0 {
            // Keep the slot consistent with C (pushed, fd<0 → ENOSPC).
            shms[idx].fd = -1;
            return -libc::ENOSPC;
        }
        let shm = &mut shms[idx];
        shm.fd = fd;
        shm.stats.shm_segsz = 0;
        shm.stats.shm_perm.mode = (shmflg & 0o777) as u16;
        shm.stats.shm_segsz = shm_size as u64;
        shm.stats.shm_cpid = config.process.as_ref().unwrap().borrow().pgid;
        shm.key = shm_key;
        shm.valid = true;
        shm.mappings = Vec::new();
    } else {
        if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
            return -libc::EEXIST;
        }
        let shm = &shms[shm_index];
        if shm_size != 0 && shm_size as u64 != shm.stats.shm_segsz {
            return -libc::EINVAL;
        }
    }
    ipc_object_id(shm_index, shms[shm_index].generation)
}

/// `sysvipc_do_rmid()` — free a fully-unmapped segment.
fn do_rmid(ns: &NsRef, shm_index: usize) {
    let fd = {
        let mut nsb = ns.borrow_mut();
        let shm = &mut nsb.shms[shm_index];
        shm.valid = false;
        shm.rmid_pending = false;
        shm.generation = shm.generation.wrapping_add(1);
        let fd = shm.fd;
        shm.fd = -1;
        shm.mappings = Vec::new();
        fd
    };
    // Close the backing fd in the helper process.
    let request = HelperRequest {
        op: HelperOp::Free as i32,
        fd,
        size: 0,
        key: 0,
    };
    send_helper_request(&request, &mut []);
}

/// `sysvipc_shm_memmap_destructor()` equivalent — `remove_mapping`
/// handles unlinking + pending RMID; see `remove_mapping`.

/// `sysvipc_shm_wake_pending_shmat()` — restart a tracee that was
/// waiting for the shmat socket round-trip.
fn wake_pending_shmat() {
    let mut woken = false;
    for_each_tracee_in_ns(None, -1, |other_tracee, other_config| {
        // C `return`s from inside the loop — wake only the first waiter.
        if woken {
            return;
        }
        if other_config.wait_reason == WaitReason::ShmatHelperBusy {
            woken = true;
            // Restart shmat with socket(AF_UNIX, SOCK_SEQPACKET, 0).
            wake_tracee(other_tracee, other_config, 0);
            register_chained_syscall(
                other_tracee,
                Sysnum::socket,
                [libc::AF_UNIX as Word, SOCK_SEQPACKET as Word, 0, 0, 0, 0],
            );
            other_config.chain_state = ChainState::ShmatSocket;
        }
    });
}

pub fn shmat(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let shm_index = match lookup_ipc_object(tracee, ns.borrow().shms.len(), |i| {
        let s = &ns.borrow().shms[i];
        (s.valid, s.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };
    config.waiting_object_index = shm_index;

    // Register the mapping for this process (prevents IPC_RMID racing
    // a shmat in flight).
    let proc = config.process.as_ref().unwrap().clone();
    let mapping_index = {
        let mut p = proc.borrow_mut();
        p.insert_mapping(SharedMemMap {
            addr: 0,
            size: 0,
            shm_index,
        })
    };
    ns.borrow_mut().shms[shm_index].mappings.push(MapRef {
        process: proc_id(&proc),
        index: mapping_index,
    });

    // Wait if another tracee's shmat is in flight.
    let mut busy = false;
    for_each_tracee_in_ns(None, tracee.pid, |_other_tracee, other_config| {
        if other_config.chain_state > ChainState::ShmatSocket
            && other_config.chain_state <= ChainState::ShmatMmap
        {
            busy = true;
        }
    });
    if busy {
        config.wait_reason = WaitReason::ShmatHelperBusy;
        return 0;
    }

    // Start the chain with socket(AF_UNIX, SOCK_SEQPACKET, 0).
    set_sysnum(tracee, Sysnum::socket);
    poke_reg(tracee, Reg::Sysarg1, libc::AF_UNIX as Word);
    poke_reg(tracee, Reg::Sysarg2, SOCK_SEQPACKET as Word);
    poke_reg(tracee, Reg::Sysarg3, 0);
    config.chain_state = ChainState::ShmatSocket;
    0
}

/// `sysvipc_shm_find_pending_mapping()` — the size-0 mapping for
/// `shm_index` in this process.
fn find_pending_mapping(config: &Sysvipc, shm_index: usize) -> MapRef {
    let proc = config.process.as_ref().unwrap();
    let p = proc.borrow();
    for (i, m) in p.mapped_shms.iter().enumerate() {
        if let Some(m) = m {
            if m.size == 0 && m.shm_index == shm_index {
                return MapRef {
                    process: proc_id(proc),
                    index: i,
                };
            }
        }
    }
    unreachable!("No pending mapping found");
}

/// Remove a mapping entry from both the process and the shm lists, and
/// run the destructor semantics (pending RMID).
fn remove_mapping(config: &Sysvipc, mref: MapRef) {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let shm_index;
    {
        let proc = config.process.as_ref().unwrap();
        let mut p = proc.borrow_mut();
        let m = p.mapped_shms[mref.index].take().unwrap();
        shm_index = m.shm_index;
    }
    {
        let mut nsb = ns.borrow_mut();
        nsb.shms[shm_index].mappings.retain(|r| *r != mref);
    }
    let empty = ns.borrow().shms[shm_index].mappings.is_empty();
    if empty && ns.borrow().shms[shm_index].rmid_pending {
        do_rmid(&ns, shm_index);
    }
}

/// `sysvipc_shmat_chain()` — advance the shmat socket→connect→recvmsg→
/// mmap chain one step.
pub fn shmat_chain(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    debug_assert!(config.waiting_object_index < ns.borrow().shms.len());
    debug_assert!(ns.borrow().shms[config.waiting_object_index].valid);

    match config.chain_state {
        ChainState::ShmatSocket => {
            config.shmat_socket_fd =
                peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64 as i32;
            if config.shmat_socket_fd < 0 {
                config.chain_state = ChainState::NotChained;
                let mref = find_pending_mapping(config, config.waiting_object_index);
                remove_mapping(config, mref);
                wake_pending_shmat();
                return -libc::ENOMEM;
            }
            let guest_addr =
                peek_reg(tracee, RegVersion::Current, Reg::StackPointer) - sockaddr_un_len();
            if guest_addr == 0 {
                config.chain_state = ChainState::NotChained;
                let mref = find_pending_mapping(config, config.waiting_object_index);
                remove_mapping(config, mref);
                wake_pending_shmat();
                return -libc::ENOMEM;
            }
            let addr = helper_addr();
            if write_data(tracee, guest_addr, &addr) < 0 {
                config.chain_state = ChainState::NotChained;
                let mref = find_pending_mapping(config, config.waiting_object_index);
                remove_mapping(config, mref);
                wake_pending_shmat();
                return -libc::ENOMEM;
            }
            register_chained_syscall(
                tracee,
                Sysnum::connect,
                [
                    config.shmat_socket_fd as Word,
                    guest_addr,
                    sockaddr_un_len(),
                    0,
                    0,
                    0,
                ],
            );
            config.shmat_guest_buf = guest_addr;
            config.chain_state = ChainState::ShmatConnect;
            1
        }
        ChainState::ShmatConnect => {
            if peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64 != 0 {
                return shmat_fail_close(tracee, config);
            }
            let Ok(pointers) = recvmsg_pointers(tracee, config.shmat_guest_buf, true) else {
                return shmat_fail_close(tracee, config);
            };
            let shm_fd = ns.borrow().shms[config.waiting_object_index].fd;
            let request = HelperRequest {
                op: HelperOp::Distribute as i32,
                fd: shm_fd,
                size: 0,
                key: 0,
            };
            send_helper_request(&request, &mut []);
            register_chained_syscall(
                tracee,
                Sysnum::recvmsg,
                [
                    config.shmat_socket_fd as Word,
                    pointers.msghdr_ptr,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            config.chain_state = ChainState::ShmatRecvmsg;
            1
        }
        ChainState::ShmatRecvmsg => {
            let Ok(pointers) = recvmsg_pointers(tracee, config.shmat_guest_buf, false) else {
                return shmat_fail_close(tracee, config);
            };
            // cmsghdr: len(8) level(4) type(4) on 64-bit.
            let cmsg_len = std::mem::size_of::<Word>() + 8;
            let mut cmsg = vec![0u8; cmsg_len];
            if read_data(tracee, &mut cmsg, pointers.cmsg_control_ptr) < 0 {
                return shmat_fail_close(tracee, config);
            }
            let cmsg_level = i32::from_ne_bytes(
                cmsg[std::mem::size_of::<Word>()..std::mem::size_of::<Word>() + 4]
                    .try_into()
                    .unwrap(),
            );
            let cmsg_type =
                i32::from_ne_bytes(cmsg[std::mem::size_of::<Word>() + 4..].try_into().unwrap());
            if cmsg_level != libc::SOL_SOCKET || cmsg_type != SCM_RIGHTS {
                return shmat_fail_close(tracee, config);
            }
            let mut fd_buf = [0u8; 4];
            if read_data(
                tracee,
                &mut fd_buf,
                pointers.cmsg_control_ptr + cmsg_len as Word,
            ) < 0
            {
                return shmat_fail_close(tracee, config);
            }
            let fd = i32::from_ne_bytes(fd_buf);
            if fd as u32 > 0xFFFF {
                return shmat_fail_close(tracee, config);
            }
            config.shmat_mem_fd = fd;

            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
            let map_size = {
                let nsb = ns.borrow();
                (nsb.shms[config.waiting_object_index].stats.shm_segsz + (page_size - 1))
                    & !(page_size - 1)
            };
            let mmap_sysnum =
                if detranslate_sysnum(get_abi(tracee), Sysnum::mmap2) != SYSCALL_AVOIDER {
                    Sysnum::mmap2
                } else {
                    Sysnum::mmap
                };
            register_chained_syscall(
                tracee,
                mmap_sysnum,
                [
                    0,
                    map_size,
                    (libc::PROT_READ | libc::PROT_WRITE) as Word,
                    libc::MAP_SHARED as Word,
                    fd as Word,
                    0,
                ],
            );
            config.chain_state = ChainState::ShmatMmap;
            1
        }
        ChainState::ShmatMmap => {
            let addr = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
            let mref = find_pending_mapping(config, config.waiting_object_index);
            let proc = config.process.as_ref().unwrap().clone();
            {
                let mut p = proc.borrow_mut();
                let m = p.mapped_shms[mref.index].as_mut().unwrap();
                m.addr = addr;
                m.size = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as usize;
            }
            register_chained_syscall(
                tracee,
                Sysnum::close,
                [config.shmat_mem_fd as Word, 0, 0, 0, 0, 0],
            );
            register_chained_syscall(
                tracee,
                Sysnum::close,
                [config.shmat_socket_fd as Word, 0, 0, 0, 0, 0],
            );
            force_chain_final_result(tracee, addr);
            config.chain_state = ChainState::NotChained;
            wake_pending_shmat();
            1
        }
        _ => {
            debug_assert!(false, "Invalid chain_state in sysvipc_shmat_chain");
            0
        }
    }
}

/// `fail_close_socket:` — chain a close of the socket and fail shmat.
fn shmat_fail_close(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    register_chained_syscall(
        tracee,
        Sysnum::close,
        [config.shmat_socket_fd as Word, 0, 0, 0, 0, 0],
    );
    force_chain_final_result(tracee, (-(libc::ENOMEM as i64)) as Word);
    config.chain_state = ChainState::NotChained;
    let mref = find_pending_mapping(config, config.waiting_object_index);
    remove_mapping(config, mref);
    wake_pending_shmat();
    1
}

fn sockaddr_un_len() -> Word {
    std::mem::size_of::<libc::sockaddr_un>() as Word
}

fn helper_addr() -> Vec<u8> {
    // struct sockaddr_un { sa_family(2), sun_path[108] }
    let mut addr = vec![0u8; sockaddr_un_len() as usize];
    addr[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
    HELPER.with(|h| {
        if let Some(conn) = h.borrow().as_ref() {
            addr[2..2 + SHMHELPER_SOCKET_LEN].copy_from_slice(&conn.addr);
        }
    });
    addr
}

pub fn shmdt(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
    let proc = config.process.as_ref().unwrap().clone();
    let found = {
        let p = proc.borrow();
        p.mapped_shms
            .iter()
            .position(|m| m.as_ref().map(|m| m.addr == addr).unwrap_or(false))
    };
    let Some(index) = found else {
        return -libc::EINVAL;
    };
    let (size, shm_index) = {
        let p = proc.borrow();
        let m = p.mapped_shms[index].as_ref().unwrap();
        (m.size, m.shm_index)
    };
    set_sysnum(tracee, Sysnum::munmap);
    poke_reg(tracee, Reg::Sysarg2, size as Word);
    config.chain_state = ChainState::Single;
    // Removing the mapping runs the destructor semantics (pending RMID).
    let mref = MapRef {
        process: proc_id(&proc),
        index,
    };
    {
        let mut p = proc.borrow_mut();
        p.mapped_shms[index] = None;
    }
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    ns.borrow_mut().shms[shm_index]
        .mappings
        .retain(|r| *r != mref);
    let empty = ns.borrow().shms[shm_index].mappings.is_empty();
    if empty && ns.borrow().shms[shm_index].rmid_pending {
        do_rmid(&ns, shm_index);
    }
    0
}

/// `sysvipc_shm_update_stats()` — recount nattch.
fn update_stats(shm: &mut SharedMem) {
    shm.stats.shm_nattch = shm.mappings.len() as u64;
}

pub fn shmctl(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let shm_index = match lookup_ipc_object(tracee, ns.borrow().shms.len(), |i| {
        let s = &ns.borrow().shms[i];
        (s.valid, s.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let cmd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i32;
    let buf = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);

    match cmd {
        c if c == IPC_RMID || c == IPC_RMID | SYSVIPC_IPC_64 => {
            let empty = ns.borrow().shms[shm_index].mappings.is_empty();
            if empty {
                do_rmid(&ns, shm_index);
            } else {
                ns.borrow_mut().shms[shm_index].rmid_pending = true;
            }
            0
        }
        c if c == IPC_STAT => {
            let bytes = {
                let mut nsb = ns.borrow_mut();
                let shm = &mut nsb.shms[shm_index];
                update_stats(shm);
                unsafe {
                    std::slice::from_raw_parts(
                        &shm.stats as *const ShmidDs as *const u8,
                        std::mem::size_of::<ShmidDs>(),
                    )
                    .to_vec()
                }
            };
            write_data(tracee, buf, &bytes)
        }
        _ => -libc::EINVAL,
    }
}

/// `sysvipc_shm_inherit_process()` — clone the parent's mappings into
/// the child's list; each shm's mapping list gains the child entries.
pub fn inherit_process(
    parent: &SysVIpcProcess,
    child: &mut SysVIpcProcess,
    ns: &NsRef,
    child_rc: &ProcRef,
) {
    let child_id = proc_id(child_rc);
    for m in parent.mapped_shms.iter().flatten() {
        let index = child.insert_mapping(m.clone());
        ns.borrow_mut().shms[m.shm_index].mappings.push(MapRef {
            process: child_id,
            index,
        });
    }
}

/// `sysvipc_shm_remove_mappings_from_process()` — on execve, drop every
/// mapping of this process, running pending RMIDs that unblocked.
pub fn remove_mappings_from_process(
    process: &mut SysVIpcProcess,
    ns: Option<&NsRef>,
    this_proc: &ProcRef,
) {
    let Some(ns) = ns else { return };
    let this_id = proc_id(this_proc);
    // Collect (slot_index, mapping) pairs before clearing.
    let taken: Vec<(usize, SharedMemMap)> = process
        .mapped_shms
        .iter()
        .enumerate()
        .filter_map(|(i, m)| m.clone().map(|m| (i, m)))
        .collect();
    process.mapped_shms.clear();
    let mut pending_rmid = Vec::new();
    {
        let mut nsb = ns.borrow_mut();
        for (index, m) in taken {
            let shm = &mut nsb.shms[m.shm_index];
            shm.mappings
                .retain(|r| !(r.process == this_id && r.index == index));
            if shm.mappings.is_empty() && shm.rmid_pending {
                pending_rmid.push(m.shm_index);
            }
        }
    }
    for shm_index in pending_rmid {
        do_rmid(ns, shm_index);
    }
}

/// `sysvipc_shm_fill_proc()` — the "/proc/sysvipc/shm" listing.
pub fn fill_proc(w: &mut dyn std::io::Write, ns: &SysVIpcNamespace) {
    let _ = write!(w, "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n");
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    for (shm_index, shm) in ns.shms.iter().enumerate() {
        if !shm.valid {
            continue;
        }
        // Bug-compatible with C: masks with `~page_size`, not `~(page_size - 1)`.
        let map_size = (shm.stats.shm_segsz + (page_size - 1)) & !page_size;
        let _ = write!(
            w,
            "{:10} {:10}  {:4o} {:21} {:5} {:5}  {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:21} {:21}\n",
            shm.key,
            ipc_object_id(shm_index, shm.generation),
            shm.stats.shm_perm.mode,
            shm.stats.shm_segsz,
            shm.stats.shm_cpid,
            shm.stats.shm_lpid,
            shm.mappings.len() as u64,
            shm.stats.shm_perm.uid,
            shm.stats.shm_perm.gid,
            shm.stats.shm_perm.cuid,
            shm.stats.shm_perm.cgid,
            shm.stats.shm_atime,
            shm.stats.shm_dtime,
            shm.stats.shm_ctime,
            map_size,
            0u64,
        );
    }
}

/// `sysvipc_shm_do_allocate()` — the backing-fd factory, run inside the
/// helper process. tmpfile()+ftruncate on Linux.
fn do_allocate(size: usize) -> i32 {
    unsafe {
        let f = libc::tmpfile();
        if f.is_null() {
            return -libc::ENOSPC;
        }
        let fd = libc::dup(libc::fileno(f));
        libc::fclose(f);
        if fd < 0 {
            return -libc::ENOSPC;
        }
        if libc::ftruncate(fd, size as i64) == -1 {
            libc::close(fd);
            return -libc::ENOSPC;
        }
        fd
    }
}

/// `sysvipc_shm_helper_main()` — the detached helper: bind a temp unix
/// socket, print its path on stdout, then serve requests on stdin.
pub fn shm_helper_main() -> ! {
    use std::io::Write as _;
    let socket_server_fd = unsafe { libc::socket(libc::AF_UNIX, SOCK_SEQPACKET, 0) };

    let mut path = Vec::new();
    for i in 0.. {
        let Some(p) = crate::path::temp::create_temp_name("prootshm") else {
            unsafe { libc::_exit(1) };
        };
        let p = {
            // mktemp semantics — create the name.
            let _ = std::fs::File::create(&p);
            let _ = std::fs::remove_file(&p);
            p
        };
        if p.len() > SHMHELPER_SOCKET_LEN {
            unsafe { libc::close(socket_server_fd) };
            eprintln!("proot-shm-helper: Temporary path too long");
            unsafe { libc::_exit(1) };
        }
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as u16;
        addr.sun_path[..p.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(p.as_ptr() as *const i8, p.len())
        });
        let bound = unsafe {
            libc::bind(
                socket_server_fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as u32,
            )
        };
        if bound == 0 {
            path = p.into_bytes();
            break;
        }
        if i >= 64 {
            unsafe { libc::close(socket_server_fd) };
            unsafe { libc::_exit(1) };
        }
    }

    if unsafe { libc::listen(socket_server_fd, 1) } < 0 {
        unsafe { libc::_exit(0) };
    }
    // Report the socket path to the launcher.
    let mut out = [0u8; SHMHELPER_SOCKET_LEN];
    out[..path.len()].copy_from_slice(&path);
    let _ = std::io::stdout().write_all(&out);
    let _ = std::io::stdout().flush();

    loop {
        let mut request: HelperRequest = unsafe { std::mem::zeroed() };
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                &mut request as *mut _ as *mut u8,
                std::mem::size_of::<HelperRequest>(),
            )
        };
        let status = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
        if status == 0 {
            break;
        }
        if status < 0 {
            if crate::path::errno() == libc::EINTR {
                continue;
            }
            break;
        }
        if status as usize != buf.len() {
            break;
        }
        match request.op {
            x if x == HelperOp::Alloc as i32 => {
                let fd = do_allocate(request.size);
                unsafe {
                    libc::write(1, &fd as *const i32 as *const _, 4);
                }
            }
            x if x == HelperOp::Free as i32 => unsafe {
                libc::close(request.fd);
            },
            x if x == HelperOp::Distribute as i32 => {
                let client = unsafe {
                    libc::accept(socket_server_fd, std::ptr::null_mut(), std::ptr::null_mut())
                };
                if client >= 0 {
                    sendfd(client, request.fd);
                    unsafe { libc::close(client) };
                }
            }
            _ => {}
        }
    }
    unsafe { libc::_exit(0) }
}

/// `SCM_RIGHTS` fd transfer (helper side).
fn sendfd(socket: i32, fd: i32) {
    unsafe {
        let mut data = 0u8;
        let mut iov = libc::iovec {
            iov_base: &mut data as *mut _ as *mut _,
            iov_len: 1,
        };
        let mut cmsg_space = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_space.as_mut_ptr() as *mut _;
        msg.msg_controllen = 20;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = SCM_RIGHTS;
        (*cmsg).cmsg_len = 20;
        let fd_ptr = libc::CMSG_DATA(cmsg) as *mut i32;
        *fd_ptr = fd;
        libc::sendmsg(socket, &msg, 0);
    }
}
