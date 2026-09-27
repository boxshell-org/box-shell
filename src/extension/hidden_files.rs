//! hidden_files extension — port of
//! extension/hidden_files/hidden_files.c.
//!
//! Filters getdents/getdents64 results so files with `HIDDEN_PREFIX`
//! (`.proot`) are invisible to the guest — used to hide link2symlink's
//! metadata sidecars and glue artifacts.

use crate::extension::Event;
use crate::fpath::FixedPath;
use crate::path::belongs_to_guestfs;
use crate::sysnum::Sysnum;
use crate::syscall::chain::register_chained_syscall;
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{get_sysnum, peek_reg, poke_reg, Reg, RegVersion};
use crate::tracee::Tracee;
use crate::Word;

const HIDDEN_PREFIX: &[u8] = b".proot";

#[derive(Default)]
pub struct HiddenFiles;

/// `handle_getdents()` — copy the getdents buffer minus hidden entries
/// back over the tracee's buffer; when nothing survives, chain another
/// getdents call instead of returning 0 bytes early.
fn handle_getdents(tracee: &mut Tracee) -> i32 {
    let sysnum = get_sysnum(tracee, RegVersion::Original);
    let is_64 = match sysnum {
        Sysnum::getdents64 => true,
        Sysnum::getdents => false,
        _ => return 0,
    };

    let res = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    if res == 0 || (res as i64) <= 0 {
        return 0;
    }
    let res = res as usize;

    let orig_start = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    let count = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);

    // Only filter directories inside the guest rootfs.
    let mut path = FixedPath::new();
    let fd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32;
    if crate::path::readlink_proc_pid_fd(tracee.pid, fd, &mut path).is_err() {
        return 0;
    }
    if !belongs_to_guestfs(tracee, path.as_bytes()) {
        return 0;
    }

    let mut orig = vec![0u8; count as usize];
    if read_data(tracee, &mut orig[..res], orig_start) < 0 {
        return -libc::EIO;
    }

    // Walk dirents; copy out non-hidden ones.
    //   linux_dirent64: ino(8) off(8) reclen(2) type(1) name[]
    //   linux_dirent:   ino(8) off(8) reclen(2) name[]
    let name_off = if is_64 { 19usize } else { 18usize };
    let mut copy: Vec<u8> = Vec::with_capacity(count as usize);
    let mut ptr = 0usize;
    while ptr + 18 <= res {
        let reclen = u16::from_ne_bytes([orig[ptr + 16], orig[ptr + 17]]) as usize;
        if reclen < 18 || ptr + reclen > res {
            break;
        }
        let name = &orig[ptr + name_off..ptr + reclen];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        if !name.starts_with(HIDDEN_PREFIX) {
            copy.extend_from_slice(&orig[ptr..ptr + reclen]);
        }
        ptr += reclen;
    }

    if copy.is_empty() {
        // Everything was hidden: re-issue the syscall for the next batch.
        let fd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
        let s = if is_64 { Sysnum::getdents64 } else { Sysnum::getdents };
        register_chained_syscall(tracee, s, [fd, orig_start, count, 0, 0, 0]);
    } else {
        if write_data(tracee, orig_start, &copy) < 0 {
            return -libc::EIO;
        }
        poke_reg(tracee, Reg::SysargResult, copy.len() as Word);
    }
    0
}

impl HiddenFiles {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::ChainedExit | Event::SysExitEnd { .. } => handle_getdents(tracee),
            _ => 0,
        }
    }
    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        &FILTERED_SYSNUMS
    }
    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self::default()
    }
}

static FILTERED_SYSNUMS: &[(Sysnum, Word)] = &[
    (Sysnum::getdents, FILTER_SYSEXIT),
    (Sysnum::getdents64, FILTER_SYSEXIT),
];
