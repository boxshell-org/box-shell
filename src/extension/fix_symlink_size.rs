//! fix_symlink_size extension — port of
//! extension/fix_symlink_size/fix_symlink_size.c.
//!
//! link2symlink's fake hard links are real symlinks on the host; lstat()
//! on them reports the target-path length, not the apparent file size.
//! This extension rewrites st_size to the symlink target length so the
//! fake link looks like the real file.

use crate::PATH_MAX;
use crate::Word;
use crate::extension::Event;
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, read_string, write_data};
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg};

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
    // `size` includes the terminator read_string wrote.
    let path = std::ffi::CStr::from_bytes_with_nul(&original[..size as usize]).unwrap_or_default();

    // Not a link → nothing to fix.
    let statl = match crate::sys::lstat(path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    if (statl.st_mode & libc::S_IFMT) != libc::S_IFLNK {
        return 0;
    }

    let mut target = [0u8; PATH_MAX];
    let size = crate::sys::readlink(path, &mut target);
    if size < 0 {
        return -crate::sys::errno();
    }

    // Overwrite st_size with the target length.
    let stat_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
    let mut st: libc::stat = crate::sys::zeroed();
    if read_data(tracee, crate::sys::as_bytes_mut(&mut st), stat_addr) < 0 {
        return 0;
    }
    st.st_size = size as i64;
    if write_data(tracee, stat_addr, crate::sys::as_bytes(&st)) < 0 {
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
        FILTERED_SYSNUMS
    }
    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self
    }
}

static FILTERED_SYSNUMS: &[(Sysnum, Word)] = &[
    (Sysnum::lstat, FILTER_SYSEXIT),
    (Sysnum::lstat64, FILTER_SYSEXIT),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, TempDir, fork_child, test_tracee, use_arena_stack};
    use crate::tracee::reg::{poke_reg, save_current_regs, set_sysnum};

    /// Arm a synthetic successful lstat: path ptr + stat buffer in arena.
    fn setup(t: &mut Tracee, arena: &mut Arena, host_path: &[u8], sysnum: Sysnum) -> usize {
        use_arena_stack(t, arena);
        let poff = 0x800usize;
        arena.local()[poff..poff + host_path.len()].copy_from_slice(host_path);
        arena.local()[poff + host_path.len()] = 0;
        let soff = 0x1000usize;
        // Current bank holds result=0 + args; snapshot into the banks the
        // handler reads: Modified.Sysarg1 (path), Original (sysnum, buf).
        poke_reg(t, Reg::Sysarg1, arena.addr() + poff as u64);
        poke_reg(t, Reg::Sysarg2, arena.addr() + soff as u64);
        set_sysnum(t, sysnum);
        poke_reg(t, Reg::SysargResult, 0);
        save_current_regs(t, RegVersion::Modified);
        save_current_regs(t, RegVersion::Original);
        soff
    }

    #[test]
    fn lstat_symlink_size_becomes_target_len() {
        let td = TempDir::new("fixss");
        td.file("target_file", b"");
        td.symlink("target_file", "lnk");
        // Literal path — td.abs() would canonicalize the symlink away.
        let link = format!("{}/lnk", td.path().display()).into_bytes();
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        // Fake a successful lstat with st_size=9999.
        let soff = setup(&mut t, &mut arena, &link, Sysnum::lstat);
        let mut st: libc::stat = crate::sys::zeroed();
        st.st_size = 9999;
        arena.local()[soff..soff + size_of::<libc::stat>()]
            .copy_from_slice(crate::sys::as_bytes(&st));
        assert_eq!(handle_sysexit_end(&mut t), 0);
        // st_size now equals strlen("target_file").
        let mut st2: libc::stat = crate::sys::zeroed();
        crate::sys::as_bytes_mut(&mut st2)
            .copy_from_slice(&arena.local()[soff..soff + size_of::<libc::stat>()]);
        assert_eq!(st2.st_size, "target_file".len() as i64);
    }

    #[test]
    fn non_link_and_failure_untouched() {
        let td = TempDir::new("fixss");
        td.file("real", b"");
        let real = td.abs("real");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        let soff = setup(&mut t, &mut arena, &real, Sysnum::lstat);
        let mut st: libc::stat = crate::sys::zeroed();
        st.st_size = 4242;
        arena.local()[soff..soff + size_of::<libc::stat>()]
            .copy_from_slice(crate::sys::as_bytes(&st));
        // Regular file -> st_size preserved.
        assert_eq!(handle_sysexit_end(&mut t), 0);
        let mut st2: libc::stat = crate::sys::zeroed();
        crate::sys::as_bytes_mut(&mut st2)
            .copy_from_slice(&arena.local()[soff..soff + size_of::<libc::stat>()]);
        assert_eq!(st2.st_size, 4242);
        // Failed syscall (result != 0) -> untouched.
        poke_reg(&mut t, Reg::SysargResult, (-1i64) as Word);
        assert_eq!(handle_sysexit_end(&mut t), 0);
        // Wrong syscall -> untouched.
        set_sysnum(&mut t, Sysnum::open);
        save_current_regs(&mut t, RegVersion::Original);
        assert_eq!(handle_sysexit_end(&mut t), 0);
    }
}
