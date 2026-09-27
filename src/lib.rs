//! box-shell — a clean-room Rust re-implementation of PRoot:
//! user-space chroot, `mount --bind` and `binfmt_misc` built on ptrace(2).

// The crate exposes the full PRoot API surface ahead of its consumers; much
// of it is exercised only once the event loop and CLI land.
#![allow(dead_code)]

pub mod arch;
pub mod cli;
pub mod execve;
pub mod extension;
pub mod fpath;
pub mod note;
pub mod path;
pub mod ptrace;
pub mod sys;
pub mod syscall;
pub mod sysnum;
pub mod tracee;
pub mod util;

/// Machine word of the *host* architecture PRoot runs on.
pub type Word = u64;

/// PRoot's notion of a path buffer: PATH_MAX bytes including the terminator.
pub const PATH_MAX: usize = 4096;

/// NAME_MAX as enforced by the canonicalizer.
pub const NAME_MAX: usize = 255;

/// Guest-visible mount point of the host rootfs in QEMU/mixed mode.
pub const HOST_ROOTFS: &str = "/host-rootfs";

/// `strerror()` — human-readable errno text.
pub fn strerror(errno: i32) -> String {
    crate::sys::strerror(errno)
}
