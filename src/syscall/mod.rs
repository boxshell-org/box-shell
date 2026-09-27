//! Syscall translation — port of src/syscall/*.

pub mod chain;
pub mod heap;
pub mod seccomp;

use crate::fpath::FixedPath;

/// `readlink_proc_fd_state` — payload of the READLINK_PROC_FD extension
/// event (syscall.h).
pub struct ReadlinkProcFdState {
    pub pid: i32,
    pub fd: i32,
    pub host_path: FixedPath,
    pub referer: FixedPath,
}

/// Sysarg index (SYSARG_1..SYSARG_6 → 0..5).
pub const SYSARG_PATH: usize = 0;
