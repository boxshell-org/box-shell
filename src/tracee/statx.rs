//! statx emulation — port of tracee/statx.c.
//!
//! Used both when a *system* seccomp policy rejects statx (SIGSYS path,
//! `from_sigsys = true`) and at the statx sysexit stage when the kernel
//! call failed but PRoot can still answer it (e.g. old kernels).

use crate::Word;
use crate::fpath::FixedPath;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, read_string, write_data};
use crate::tracee::reg::{Reg, RegVersion, peek_reg};

/// `struct statx_timestamp`.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

/// `struct statx` — kernel-stable layout.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub __spare2: [u64; 14],
}

/// `statx_syscall_state` — STATX_SYSCALL event payload.
#[derive(Default)]
pub struct StatxSyscallState {
    pub host_path: FixedPath,
    pub statx_buf: Statx,
    pub updated_stats: bool,
}

const STATX_TYPE: u64 = 0x0001;
const STATX_MODE: u64 = 0x0002;
pub const STATX_NLINK: u64 = 0x0004;
const STATX_UID: u64 = 0x0008;
const STATX_GID: u64 = 0x0010;
const STATX_ATIME: u64 = 0x0020;
const STATX_MTIME: u64 = 0x0040;
const STATX_CTIME: u64 = 0x0080;
const STATX_INO: u64 = 0x0100;
const STATX_SIZE: u64 = 0x0200;
const STATX_BLOCKS: u64 = 0x0400;
const STATX_BTIME: u64 = 0x0800;

fn statx_ts(sec: i64, nsec: i64) -> StatxTimestamp {
    StatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    }
}

/// `handle_statx_syscall()` — answer statx() from a tracer-side lstat/stat
/// plus extension fixups.  Returns 0/-errno like a syscall result.
pub fn handle_statx_syscall(tracee: &mut Tracee, from_sigsys: bool) -> i32 {
    let rv = if from_sigsys {
        RegVersion::Current
    } else {
        RegVersion::Original
    };
    let mut state = StatxSyscallState::default();
    let mut guest_path = FixedPath::new();
    let mut do_fstat = false;

    // Read arguments and translate the path.
    let flags = peek_reg(tracee, rv, Reg::Sysarg3);
    let do_lstat = (flags & libc::AT_SYMLINK_NOFOLLOW as Word) != 0;
    let mask = peek_reg(tracee, rv, Reg::Sysarg4);
    let size = read_string(
        tracee,
        guest_path.as_mut_bytes(),
        peek_reg(tracee, rv, Reg::Sysarg2),
    );
    if size < 0 {
        return size;
    }
    guest_path.sync_len_from_nul();
    let dirfd = peek_reg(tracee, rv, Reg::Sysarg1) as i32;
    let mut status: i32;
    if size == 0 {
        return -libc::EFAULT;
    }
    if size == 1 {
        if (flags & libc::AT_EMPTY_PATH as Word) == 0 {
            return -libc::ENOENT;
        }
        match crate::path::readlink_proc_pid_fd(tracee.pid, dirfd, &mut state.host_path) {
            Ok(()) => status = 0,
            Err(e) => return e,
        }
        do_fstat = true;
    } else {
        if size as usize >= crate::PATH_MAX {
            return -libc::ENAMETOOLONG;
        }
        status = match crate::path::translate_path(
            tracee,
            &mut state.host_path,
            dirfd,
            &guest_path.as_bytes()[..size as usize - 1],
            !do_lstat,
        ) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    if status < 0 {
        return status;
    }

    if from_sigsys || peek_reg(tracee, RegVersion::Current, Reg::SysargResult) != 0 {
        // Answer from a tracer-side [l]stat of the translated path.
        let sb = if do_fstat {
            let link =
                std::ffi::CString::new(format!("/proc/{}/fd/{}", tracee.pid, dirfd)).unwrap();
            crate::sys::stat(&link)
        } else {
            let c = std::ffi::CString::new(state.host_path.as_bytes()).unwrap();
            if do_lstat {
                crate::sys::lstat(&c)
            } else {
                crate::sys::stat(&c)
            }
        };
        let sb = match sb {
            Ok(sb) => sb,
            Err(e) => {
                status = -e;
                if status >= 0 {
                    status = -libc::EPERM;
                }
                return status;
            }
        };

        // stat → statx field translation.
        state.statx_buf.stx_mask = (mask
            & (STATX_TYPE
                | STATX_MODE
                | STATX_NLINK
                | STATX_UID
                | STATX_GID
                | STATX_ATIME
                | STATX_MTIME
                | STATX_CTIME
                | STATX_INO
                | STATX_SIZE
                | STATX_BLOCKS
                | STATX_BTIME)) as u32;
        state.statx_buf.stx_blksize = sb.st_blksize as u32;
        if mask & (STATX_TYPE | STATX_MODE) != 0 {
            state.statx_buf.stx_mode = sb.st_mode as u16;
        }
        if mask & STATX_NLINK != 0 {
            state.statx_buf.stx_nlink = sb.st_nlink as u32;
        }
        if mask & STATX_UID != 0 {
            state.statx_buf.stx_uid = sb.st_uid;
        }
        if mask & STATX_GID != 0 {
            state.statx_buf.stx_gid = sb.st_gid;
        }
        if mask & STATX_ATIME != 0 {
            state.statx_buf.stx_atime = statx_ts(sb.st_atime, sb.st_atime_nsec);
        }
        if mask & STATX_MTIME != 0 {
            state.statx_buf.stx_mtime = statx_ts(sb.st_mtime, sb.st_mtime_nsec);
        }
        if mask & STATX_CTIME != 0 {
            state.statx_buf.stx_ctime = statx_ts(sb.st_ctime, sb.st_ctime_nsec);
        }
        if mask & STATX_INO != 0 {
            state.statx_buf.stx_ino = sb.st_ino;
        }
        if mask & STATX_SIZE != 0 {
            state.statx_buf.stx_size = sb.st_size as u64;
        }
        if mask & STATX_BLOCKS != 0 {
            state.statx_buf.stx_blocks = sb.st_blocks as u64;
        }
        if mask & STATX_BTIME != 0 {
            // stat() doesn't expose btime; ctime is the approximation.
            state.statx_buf.stx_btime = statx_ts(sb.st_ctime, sb.st_ctime_nsec);
        }
        state.statx_buf.stx_rdev_major = libc::major(sb.st_rdev);
        state.statx_buf.stx_rdev_minor = libc::minor(sb.st_rdev);
        state.updated_stats = true;
    } else {
        // The kernel wrote the result; read it back so extensions can
        // inspect/falsify it.
        status = read_data(
            tracee,
            crate::sys::as_bytes_mut(&mut state.statx_buf),
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg5),
        );
        if status < 0 {
            return status;
        }
    }

    // Notify extensions (STATX_SYSCALL).
    status = crate::extension::notify(
        tracee,
        &mut crate::extension::Event::StatxSyscall { state: &mut state },
    );
    if status < 0 {
        return status;
    }

    if state.updated_stats {
        status = write_data(
            tracee,
            peek_reg(tracee, RegVersion::Current, Reg::Sysarg5),
            crate::sys::as_bytes(&state.statx_buf),
        );
        if status < 0 {
            return status;
        }
    }
    0
}
