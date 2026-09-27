//! Tracee memory access — port of tracee/mem.c.
//!
//! Fast path is `process_vm_readv`/`process_vm_writev` (single syscall,
//! byte-granular); the fallback is word-wise PTRACE_PEEKDATA/POKEDATA.

use crate::tracee::reg::{is_32on64_mode, peek_reg, poke_reg, sizeof_word, Reg, RegVersion};
use crate::tracee::Tracee;
use crate::Word;

fn ptrace_peekdata(pid: i32, addr: Word) -> Result<Word, i32> {
    unsafe {
        *errno_ptr() = 0;
        let v = libc::ptrace(
            crate::ptrace::ptc::PTRACE_PEEKDATA as u32,
            pid,
            addr as usize,
            0usize,
        );
        let e = *errno_ptr();
        if e != 0 {
            return Err(if e == libc::EIO { libc::EFAULT } else { e });
        }
        Ok(v as Word)
    }
}

fn ptrace_pokedata(pid: i32, addr: Word, value: Word) -> Result<(), i32> {
    unsafe {
        *errno_ptr() = 0;
        libc::ptrace(
            crate::ptrace::ptc::PTRACE_POKEDATA as u32,
            pid,
            addr as usize,
            value as usize,
        );
        let e = *errno_ptr();
        if e != 0 {
            return Err(if e == libc::EIO { libc::EFAULT } else { e });
        }
        Ok(())
    }
}

fn errno_ptr() -> *mut i32 {
    unsafe { libc::__errno_location() }
}

fn process_vm_write(pid: i32, local: &[u8], remote: Word) -> isize {
    let liovec = libc::iovec {
        iov_base: local.as_ptr() as *mut _,
        iov_len: local.len(),
    };
    let riovec = libc::iovec {
        iov_base: remote as usize as *mut _,
        iov_len: local.len(),
    };
    unsafe { libc::process_vm_writev(pid, &liovec, 1, &riovec, 1, 0) }
}

fn process_vm_read(pid: i32, local: &mut [u8], remote: Word) -> isize {
    let liovec = libc::iovec {
        iov_base: local.as_mut_ptr() as *mut _,
        iov_len: local.len(),
    };
    let riovec = libc::iovec {
        iov_base: remote as usize as *mut _,
        iov_len: local.len(),
    };
    unsafe { libc::process_vm_readv(pid, &liovec, 1, &riovec, 1, 0) }
}

/// `write_data()` — copy `src` into `dest` in the tracee; `-errno` on error.
pub fn write_data(tracee: &Tracee, dest: Word, src: &[u8]) -> i32 {
    if src.is_empty() {
        return 0;
    }
    if process_vm_write(tracee.pid, src, dest) == src.len() as isize {
        return 0;
    }

    let ws = std::mem::size_of::<Word>();
    let full = src.len() / ws;
    let trailing = src.len() % ws;

    for i in 0..full {
        let w = Word::from_ne_bytes(src[i * ws..i * ws + ws].try_into().unwrap());
        if ptrace_pokedata(tracee.pid, dest + (i * ws) as Word, w).is_err() {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "ptrace(POKEDATA)"
            );
            return -libc::EFAULT;
        }
    }
    if trailing == 0 {
        return 0;
    }

    // Merge the trailing bytes into the last word read from the tracee.
    let mut word = match ptrace_peekdata(tracee.pid, dest + (full * ws) as Word) {
        Ok(w) => w,
        Err(_) => {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "ptrace(PEEKDATA)"
            );
            return -libc::EFAULT;
        }
    };
    let mut wb = word.to_ne_bytes();
    wb[..trailing].copy_from_slice(&src[full * ws..]);
    word = Word::from_ne_bytes(wb);
    if ptrace_pokedata(tracee.pid, dest + (full * ws) as Word, word).is_err() {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::System,
            "ptrace(POKEDATA)"
        );
        return -libc::EFAULT;
    }
    0
}

/// `writev_data()` — gather-write several buffers in one remote segment.
pub fn writev_data(tracee: &Tracee, dest: Word, srcs: &[&[u8]]) -> i32 {
    let total: usize = srcs.iter().map(|s| s.len()).sum();
    let local: Vec<libc::iovec> = srcs
        .iter()
        .map(|s| libc::iovec {
            iov_base: s.as_ptr() as *mut _,
            iov_len: s.len(),
        })
        .collect();
    let remote = libc::iovec {
        iov_base: dest as usize as *mut _,
        iov_len: total,
    };
    if unsafe {
        libc::process_vm_writev(tracee.pid, local.as_ptr(), local.len() as _, &remote, 1, 0)
    } == total as isize
    {
        return 0;
    }
    let mut off = 0u64;
    for s in srcs {
        let st = write_data(tracee, dest + off, s);
        if st < 0 {
            return st;
        }
        off += s.len() as u64;
    }
    0
}

/// `read_data()` — copy `size` bytes from the tracee into `dest`.
pub fn read_data(tracee: &Tracee, dest: &mut [u8], src: Word) -> i32 {
    if dest.is_empty() {
        return 0;
    }
    if process_vm_read(tracee.pid, dest, src) == dest.len() as isize {
        return 0;
    }

    let ws = std::mem::size_of::<Word>();
    let full = dest.len() / ws;
    let trailing = dest.len() % ws;

    for i in 0..full {
        match ptrace_peekdata(tracee.pid, src + (i * ws) as Word) {
            Ok(w) => dest[i * ws..i * ws + ws].copy_from_slice(&w.to_ne_bytes()),
            Err(_) => {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::System,
                    "ptrace(PEEKDATA)"
                );
                return -libc::EFAULT;
            }
        }
    }
    if trailing == 0 {
        return 0;
    }
    match ptrace_peekdata(tracee.pid, src + (full * ws) as Word) {
        Ok(w) => {
            dest[full * ws..].copy_from_slice(&w.to_ne_bytes()[..trailing]);
            0
        }
        Err(_) => {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "ptrace(PEEKDATA)"
            );
            -libc::EFAULT
        }
    }
}

/// `read_string()` — read a NUL-terminated string, `max_size` bytes at most;
/// returns the length *including* the terminator, or `-errno`.
pub fn read_string(tracee: &Tracee, dest: &mut [u8], src: Word) -> i32 {
    let max_size = dest.len();
    // Chunked process_vm_readv so a chunk never crosses a page boundary.
    const CHUNK: usize = 1024;
    let mut offset = 0usize;
    loop {
        if offset >= max_size {
            break;
        }
        let cur = src + offset as u64;
        let next_chunk = (cur & !(CHUNK as u64 - 1)) + CHUNK as u64;
        let mut size = (next_chunk - cur) as usize;
        size = size.min(max_size - offset);
        let n = process_vm_read(tracee.pid, &mut dest[offset..offset + size], cur);
        if n == size as isize {
            match dest[offset..offset + size].iter().position(|&b| b == 0) {
                Some(p) => return (offset + p + 1) as i32,
                None => {
                    offset += size;
                    continue;
                }
            }
        }
        break;
    }
    // Fallback: word-wise peek.
    let ws = std::mem::size_of::<Word>();
    let full = max_size / ws;
    let trailing = max_size % ws;
    for i in 0..full {
        match ptrace_peekdata(tracee.pid, src + (i * ws) as Word) {
            Ok(w) => {
                let wb = w.to_ne_bytes();
                dest[i * ws..i * ws + ws].copy_from_slice(&wb);
                if let Some(j) = wb.iter().position(|&b| b == 0) {
                    return (i * ws + j + 1) as i32;
                }
            }
            Err(_) => return -libc::EFAULT,
        }
    }
    if trailing > 0 {
        match ptrace_peekdata(tracee.pid, src + (full * ws) as Word) {
            Ok(w) => {
                let wb = w.to_ne_bytes();
                let mut j = 0;
                while j < trailing {
                    dest[full * ws + j] = wb[j];
                    if wb[j] == 0 {
                        break;
                    }
                    j += 1;
                }
                return (full * ws + j + 1) as i32;
            }
            Err(_) => return -libc::EFAULT,
        }
    }
    (full * ws) as i32
}

/// `peek_word()` — read one guest word; errno carries the failure.
pub fn peek_word(tracee: &Tracee, address: Word) -> Word {
    let mut result: Word = 0;
    let wsize = sizeof_word(tracee);
    let n = process_vm_read(
        tracee.pid,
        unsafe { std::slice::from_raw_parts_mut(&mut result as *mut _ as *mut u8, wsize) },
        address,
    );
    if n == wsize as isize {
        unsafe { *errno_ptr() = 0 };
        return result;
    }
    match ptrace_peekdata(tracee.pid, address) {
        Ok(mut w) => {
            if is_32on64_mode(tracee) {
                w &= 0xFFFF_FFFF;
            }
            w
        }
        Err(_) => 0,
    }
}

/// `poke_word()` — write one guest word; errno carries the failure.
pub fn poke_word(tracee: &Tracee, address: Word, value: Word) {
    let wsize = sizeof_word(tracee);
    let n = process_vm_write(
        tracee.pid,
        unsafe { std::slice::from_raw_parts(&value as *const _ as *const u8, wsize) },
        address,
    );
    if n == wsize as isize {
        unsafe { *errno_ptr() = 0 };
        return;
    }
    let mut v = value;
    if is_32on64_mode(tracee) {
        if let Ok(tmp) = ptrace_peekdata(tracee.pid, address) {
            v |= tmp & 0xFFFF_FFFF_0000_0000;
        } else {
            return;
        }
    }
    let _ = ptrace_pokedata(tracee.pid, address, v);
}

/// `peek_uint32()` — read 4 bytes; errno carries the failure.
pub fn peek_uint32(tracee: &Tracee, address: Word) -> u32 {
    let mut buf = [0u8; 4];
    if process_vm_read(tracee.pid, &mut buf, address) == 4 {
        unsafe { *errno_ptr() = 0 };
        return u32::from_ne_bytes(buf);
    }
    match ptrace_peekdata(tracee.pid, address) {
        Ok(w) => w as u32,
        Err(_) => 0,
    }
}

/// `poke_uint32()` — write 4 bytes; errno carries the failure.
pub fn poke_uint32(tracee: &Tracee, address: Word, value: u32) {
    let buf = value.to_ne_bytes();
    if process_vm_write(tracee.pid, &buf, address) == 4 {
        unsafe { *errno_ptr() = 0 };
        return;
    }
    if let Ok(old) = ptrace_peekdata(tracee.pid, address) {
        let v = (old & 0xFFFF_FFFF_0000_0000) | value as u64;
        let _ = ptrace_pokedata(tracee.pid, address, v);
    }
}

/// `peek_int32()`.
pub fn peek_int32(tracee: &Tracee, address: Word) -> i32 {
    peek_uint32(tracee, address) as i32
}

/// `poke_int32()`.
pub fn poke_int32(tracee: &Tracee, address: Word, value: i32) {
    poke_uint32(tracee, address, value as u32)
}

/// `peek_uint64()`.
pub fn peek_uint64(tracee: &Tracee, address: Word) -> u64 {
    let mut buf = [0u8; 8];
    if process_vm_read(tracee.pid, &mut buf, address) == 8 {
        unsafe { *errno_ptr() = 0 };
        return u64::from_ne_bytes(buf);
    }
    ptrace_peekdata(tracee.pid, address).unwrap_or_default()
}

/// `alloc_mem()` — grow the tracee stack downward by `size` bytes.
pub fn alloc_mem(tracee: &mut Tracee, size: i64) -> Word {
    debug_assert!(crate::tracee::is_in_sysenter(tracee));
    let mut sp = peek_reg(tracee, RegVersion::Current, Reg::StackPointer);
    let mut size = size;
    if sp == peek_reg(tracee, RegVersion::Original, Reg::StackPointer) {
        size += crate::arch::RED_ZONE_SIZE as i64;
    }
    if (size > 0 && sp <= size as u64) || (size < 0 && sp >= u64::MAX.wrapping_add(size as u64)) {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::Internal,
            "integer under/overflow detected in alloc_mem"
        );
        return 0;
    }
    sp = sp.wrapping_sub(size as u64);
    poke_reg(tracee, Reg::StackPointer, sp);
    sp
}

/// `clear_mem()` — zero `size` bytes in the tracee.
pub fn clear_mem(tracee: &Tracee, address: Word, size: usize) -> i32 {
    let zeros = vec![0u8; size];
    write_data(tracee, address, &zeros)
}

/// `mem_prepare_after_execve()` — on x86_64 the only post-execve work was
/// the pokedata-workaround stub, which doesn't apply; kept for parity.
pub fn mem_prepare_after_execve(_tracee: &mut Tracee) {}

/// `mem_prepare_before_first_execve()` — see above.
pub fn mem_prepare_before_first_execve(_tracee: &mut Tracee) {}

/// `read_path()` — read a NUL-terminated path (PATH_MAX bound) from the
/// tracee.
pub fn read_path(tracee: &Tracee, path: &mut crate::fpath::FixedPath, src: Word) -> i32 {
    let mut buf = [0u8; crate::PATH_MAX];
    let size = read_string(tracee, &mut buf, src);
    if size < 0 {
        return size;
    }
    path.set(&buf[..size as usize - 1]);
    size
}
