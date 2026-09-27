//! statx syscall state — port of tracee/statx.h.

/// `statx_syscall_state` — STATX_SYSCALL event payload.
pub struct StatxSyscallState {
    /// The original statx output buffer in the tracee.
    pub statxbuf_user_address: crate::Word,
    /// User-supplied flags/mask/path.
    pub flags: crate::Word,
    pub mask: crate::Word,
    pub path: crate::fpath::FixedPath,
}
