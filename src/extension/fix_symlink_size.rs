//! fix_symlink_size extension — port of
//! extension/fix_symlink_size/fix_symlink_size.c.
//!
//! link2symlink's fake hard links are real symlinks on the host; lstat()
//! on them reports the target-path length, not the apparent file size.
//! This extension rewrites st_size to the symlink target length so the
//! fake link looks like the real file.

use std::ffi::CString;

use crate::extension::Event;
use crate::sysnum::Sysnum;
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::tracee::mem::{read_data, read_string, write_data};
use crate::tracee::reg::{get_sysnum, peek_reg, Reg, RegVersion};
use crate::tracee::Tracee;
use crate::Word;
use crate::PATH_MAX;

#[derive(Default)]
pub struct FixSymlinkSize;

/// `handle_sysexit_end()` — after a successful lstat on a symlink, set
/// `st_size` to the length of its target.
fn handle_sysexit_end(tracee: &mut Tracee) -> i32 {
    match get_sysnum(tracee, RegVersion::Original) {
        Sysnum::lstat | Sysnum::lstat64 => {}
        _ => return 0,
    }

    // Override only on success.
    if peek_reg(tracee, RegVersion::Current, Reg::SysargResult) != 0 {
        return 0;
    }

    // Read the (translated) host path — link2symlink will already have
    // resolved any fake hard link, so a symlink here is a real one.
    let mut original = [0u8; PATH_MAX];
    let size = read_string(
        tracee,
        &mut original,
        peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1),
    );
    if size < 0 {
        return size;
    }
    if size as usize >= PATH_MAX {
        return -libc::ENAMETOOLONG;
    }
    let path = CString::new(&original[..size as usize - 1]).unwrap_or_default();

    // Not a link → nothing to fix.
    let mut statl: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(path.as_ptr(), &mut statl) } < 0 {
        return -crate::path::errno();
    }
    if (statl.st_mode & libc::S_IFMT) != libc::S_IFLNK {
        return 0;
    }

    let mut target = [0u8; PATH_MAX];
    let size = unsafe { libc::readlink(path.as_ptr(), target.as_mut_ptr() as *mut i8, PATH_MAX) };
    if size < 0 {
        return -crate::path::errno();
    }

    // Overwrite st_size with the target length.
    let stat_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
    let raw = unsafe {
        std::slice::from_raw_parts_mut(
            &mut statl as *mut libc::stat as *mut u8,
            std::mem::size_of::<libc::stat>(),
        )
    };
    if read_data(tracee, raw, stat_addr) < 0 {
        return 0;
    }
    statl.st_size = size as i64;
    if write_data(tracee, stat_addr, raw) < 0 {
        return -libc::EIO;
    }
    0
}

impl FixSymlinkSize {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::SysExitEnd { .. } => handle_sysexit_end(tracee),
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
    (Sysnum::lstat, FILTER_SYSEXIT),
    (Sysnum::lstat64, FILTER_SYSEXIT),
];
