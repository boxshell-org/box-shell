//! Path virtualization: canonicalization, bindings, /proc emulation, glue,
//! temp files — port of src/path/*.

pub mod binding;
pub mod canon;
pub mod f2fs;
pub mod glue;
pub mod proc_emul;
pub mod temp;

use crate::fpath::FixedPath;
use crate::PATH_MAX;

/// Result of `compare_paths()` (path.h `Comparison`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Comparison {
    PathsAreEqual,
    Path1IsPrefix,
    Path2IsPrefix,
    PathsAreNotComparable,
}

/// Which side of a binding a lookup walks (`Side` in binding.h).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Side {
    Pending,
    Guest,
    Host,
}

/// Final-component semantics of the canonicalizer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Finality {
    NotFinal,
    Normal,
    Slash,
    Dot,
}

impl Finality {
    #[inline]
    pub fn is_final(self) -> bool {
        !matches!(self, Finality::NotFinal)
    }
}

pub const NOT_FINAL: Finality = Finality::NotFinal;
pub const FINAL_NORMAL: Finality = Finality::Normal;
pub const FINAL_SLASH: Finality = Finality::Slash;
pub const FINAL_DOT: Finality = Finality::Dot;

/// `compare_paths()` on byte strings.
pub fn compare_paths(p1: &[u8], p2: &[u8]) -> Comparison {
    compare_paths2(p1, p2)
}

pub fn compare_paths2(path1: &[u8], path2: &[u8]) -> Comparison {
    let mut length1 = path1.len();
    let mut length2 = path2.len();
    if length1 == 0 || length2 == 0 {
        return Comparison::PathsAreNotComparable;
    }
    if path1[length1 - 1] == b'/' {
        length1 -= 1;
    }
    if path2[length2 - 1] == b'/' {
        length2 -= 1;
    }
    // C reads the byte right after the shortest path — its NUL terminator
    // when lengths are equal.
    let (length_min, sentinel) = if length1 < length2 {
        (length1, path2[length1])
    } else {
        (length2, path1.get(length2).copied().unwrap_or(0))
    };
    if sentinel != b'/' && sentinel != 0 {
        return Comparison::PathsAreNotComparable;
    }
    if path1[..length_min] != path2[..length_min] {
        return Comparison::PathsAreNotComparable;
    }
    match length1.cmp(&length2) {
        std::cmp::Ordering::Equal => Comparison::PathsAreEqual,
        std::cmp::Ordering::Less => Comparison::Path1IsPrefix,
        std::cmp::Ordering::Greater => Comparison::Path2IsPrefix,
    }
}

/// `join_paths()` for two paths into `result`.
pub fn join_paths2(result: &mut FixedPath, p1: &[u8], p2: &[u8]) -> Result<(), i32> {
    result.set(b"");
    result.push_component(p1)?;
    result.push_component(p2)
}

/// `readlink(/proc/<pid>/fd/<fd>)`.
pub fn readlink_proc_pid_fd(pid: i32, fd: i32, path: &mut FixedPath) -> Result<(), i32> {
    let link = format!("/proc/{}/fd/{}", pid, fd);
    let c = match std::ffi::CString::new(link.as_bytes()) {
        Ok(c) => c,
        Err(_) => return Err(-libc::EBADF),
    };
    let mut buf = vec![0u8; PATH_MAX];
    let n = unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr() as *mut _, PATH_MAX - 1) };
    if n < 0 {
        return Err(-libc::EBADF);
    }
    if n as usize >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    path.set(&buf[..n as usize]);
    Ok(())
}

/// `getcwd2()` — the tracee's virtual cwd (guest path) or host getcwd when
/// `tracee` is None.
pub fn getcwd2(tracee: Option<&crate::tracee::Tracee>, guest_path: &mut FixedPath) -> Result<(), i32> {
    match tracee {
        None => {
            let mut buf = vec![0u8; PATH_MAX];
            let r = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut _, PATH_MAX) };
            if r.is_null() {
                return Err(-errno());
            }
            guest_path.set(&buf);
            Ok(())
        }
        Some(t) => {
            let cwd = t.fs.borrow().cwd.clone();
            if cwd.len() >= PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            guest_path.set(cwd.as_bytes());
            Ok(())
        }
    }
}

/// `realpath2()` — canonicalize `path` (in the tracee namespace when set).
pub fn realpath2(
    tracee: Option<&mut crate::tracee::Tracee>,
    host_path: &mut FixedPath,
    path: &[u8],
    deref_final: bool,
) -> Result<(), i32> {
    match tracee {
        None => {
            let c = std::ffi::CString::new(path).map_err(|_| -libc::EINVAL)?;
            let mut buf = vec![0u8; PATH_MAX];
            let r = unsafe { libc::realpath(c.as_ptr(), buf.as_mut_ptr() as *mut _) };
            if r.is_null() {
                return Err(-errno());
            }
            host_path.set(&buf);
            Ok(())
        }
        Some(t) => crate::path::translate_path(t, host_path, libc::AT_FDCWD, path, deref_final),
    }
}

/// `belongs_to_guestfs()` — whether the translated host path lives inside the
/// guest rootfs (i.e. under the root binding, not a guest binding).
pub fn belongs_to_guestfs(tracee: &crate::tracee::Tracee, host_path: &[u8]) -> bool {
    let root = binding::get_root(tracee);
    let c = compare_paths(root.as_bytes(), host_path);
    c == Comparison::PathsAreEqual || c == Comparison::Path1IsPrefix
}

/// `which()` — resolve `command` using $PATH within the tracee's namespace.
pub fn which(
    tracee: &mut crate::tracee::Tracee,
    paths: Option<&str>,
    host_path: &mut FixedPath,
    command: &[u8],
) -> Result<(), i32> {
    let is_explicit = command.contains(&b'/');

    let mut found = false;
    if realpath2(Some(tracee), host_path, command, true).is_ok() {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let c = std::ffi::CString::new(host_path.as_bytes()).unwrap();
        if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0 {
            if is_explicit && (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::User,
                    "'{}' is not a regular file",
                    String::from_utf8_lossy(command)
                );
                return Err(-libc::EACCES);
            }
            if is_explicit && (st.st_mode & libc::S_IXUSR) == 0 {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::User,
                    "'{}' is not executable",
                    String::from_utf8_lossy(command)
                );
                return Err(-libc::EACCES);
            }
            found = true;
            let _ = realpath2(Some(tracee), host_path, command, false);
        }
    }

    if is_explicit {
        if found {
            return Ok(());
        }
        return not_found(tracee, paths, command, found);
    }

    let paths_owned: String;
    let paths = match paths {
        Some(p) => p,
        None => match std::env::var("PATH") {
            Ok(p) => {
                paths_owned = p;
                &paths_owned
            }
            Err(_) => "",
        },
    };
    if paths.is_empty() {
        return not_found(tracee, Some(paths), command, found);
    }

    for dir in paths.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        if dir.len() >= PATH_MAX || dir.len() + command.len() + 2 >= PATH_MAX {
            continue;
        }
        let mut cand = FixedPath::new();
        cand.set(dir.as_bytes());
        let _ = cand.push_component(command);
        if realpath2(Some(tracee), host_path, cand.as_bytes(), true).is_ok() {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let c = std::ffi::CString::new(host_path.as_bytes()).unwrap();
            if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0
                && (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                && (st.st_mode & libc::S_IXUSR) != 0
            {
                let _ = realpath2(Some(tracee), host_path, cand.as_bytes(), false);
                return Ok(());
            }
        }
    }
    not_found(tracee, Some(paths), command, found)
}

fn not_found(
    tracee: &mut crate::tracee::Tracee,
    paths: Option<&str>,
    command: &[u8],
    found: bool,
) -> Result<(), i32> {
    let mut cwd = FixedPath::new();
    let cwd_str = match getcwd2(Some(tracee), &mut cwd) {
        Ok(()) => cwd.to_string(),
        Err(_) => "<unknown>".to_string(),
    };
    let root = binding::get_root(tracee);
    crate::note!(
        crate::note::Severity::Error,
        crate::note::Origin::User,
        "'{}' not found (root = {}, cwd = {}, $PATH={:?})",
        String::from_utf8_lossy(command),
        root,
        cwd_str,
        paths.unwrap_or("")
    );
    if found {
        crate::note!(
            crate::note::Severity::Error,
            crate::note::Origin::User,
            "to execute a local program, use the './' prefix, for example: ./{}",
            String::from_utf8_lossy(command)
        );
    }
    Err(-1)
}

pub fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// `translate_path()` — the full guest→host canonicalization entry point.
pub fn translate_path(
    tracee: &mut crate::tracee::Tracee,
    result: &mut FixedPath,
    dir_fd: i32,
    user_path: &[u8],
    deref_final: bool,
) -> Result<(), i32> {
    let mut guest_path = FixedPath::new();

    if user_path.first() == Some(&b'/') {
        result.set(b"/");
    } else if dir_fd != libc::AT_FDCWD {
        readlink_proc_pid_fd(tracee.pid, dir_fd, result)?;
        if result.as_bytes().first() != Some(&b'/') {
            return Err(-libc::ENOTDIR);
        }
        detranslate_path(tracee, result, None)?;
    } else {
        getcwd2(Some(tracee), result)?;
    }

    crate::verbose!(
        Some(tracee),
        2,
        "vpid {}: translate(\"{}\" + \"{}\")",
        tracee.vpid,
        result,
        String::from_utf8_lossy(user_path)
    );

    let mut base = result.clone();
    let status = crate::extension::notify_guest_path(tracee, &mut base, user_path);
    if status < 0 {
        return Err(status);
    }
    if status > 0 {
        result.set(base.as_bytes());
        return finish_translate(tracee, result);
    }

    debug_assert!(result.as_bytes().first() == Some(&b'/'));
    join_paths2(&mut guest_path, result.as_bytes(), user_path)?;
    result.set(b"/");

    canon::canonicalize(tracee, guest_path.as_bytes(), deref_final, result, 0)?;

    binding::substitute_binding(tracee, Side::Guest, result)?;

    finish_translate(tracee, result)
}

fn finish_translate(tracee: &mut crate::tracee::Tracee, result: &mut FixedPath) -> Result<(), i32> {
    crate::verbose!(
        Some(tracee),
        2,
        "vpid {}:          -> \"{}\"",
        tracee.vpid,
        result
    );
    crate::extension::notify_translated_path(tracee, result)
}

/// `detranslate_path()` — strip the root prefix or substitute a binding for a
/// host path so it looks like a guest path again.  `t_referrer` is the
/// translated path of the symlink *referrer* (used to keep /proc and
/// same-binding symlink targets consistent).
pub fn detranslate_path(
    tracee: &mut crate::tracee::Tracee,
    path: &mut FixedPath,
    t_referrer: Option<&FixedPath>,
) -> Result<i32, i32> {
    if path.len() >= PATH_MAX - 1 {
        return Err(-libc::ENAMETOOLONG);
    }
    if path.as_bytes().first() != Some(&b'/') {
        return Ok(0);
    }

    let mut sanity_check = false;
    let mut follow_binding = false;

    if let Some(t_referrer) = t_referrer {
        match compare_paths(b"/proc", t_referrer.as_bytes()) {
            Comparison::Path1IsPrefix => {
                let mut proc_path = path.clone();
                let new_length = proc_emul::readlink_proc2(tracee, &mut proc_path, t_referrer)?;
                if new_length != 0 {
                    path.set(proc_path.as_bytes());
                    return Ok(new_length as i32 + 1);
                }
                follow_binding = true;
            }
            _ => {
                if !belongs_to_guestfs(tracee, t_referrer.as_bytes()) {
                    let referree = binding::get_path_binding(tracee, Side::Host, path.as_bytes());
                    let referrer = binding::get_path_binding(tracee, Side::Host, t_referrer.as_bytes());
                    if let (Some(ree), Some(rer)) = (referree, referrer) {
                        follow_binding = compare_paths(ree.as_bytes(), rer.as_bytes())
                            == Comparison::PathsAreEqual;
                    }
                }
            }
        }
    } else {
        sanity_check = true;
        follow_binding = true;
    }

    if follow_binding {
        match binding::substitute_binding(tracee, Side::Host, path) {
            Ok(0) => return Ok(0),
            Ok(1) => return Ok(path.len() as i32 + 1),
            _ => {}
        }
    }

    let root = binding::get_root(tracee);
    match compare_paths(root.as_bytes(), path.as_bytes()) {
        Comparison::Path1IsPrefix => {
            let mut prefix_length = root.as_bytes().len();
            if prefix_length == 1 {
                prefix_length = 0;
            }
            let new_length = path.len() - prefix_length;
            let bytes = path.as_bytes()[prefix_length..].to_vec();
            path.set(&bytes);
            let _ = new_length;
            Ok(path.len() as i32 + 1)
        }
        Comparison::PathsAreEqual => {
            path.set(b"/");
            Ok(2)
        }
        _ => {
            if sanity_check {
                Err(-libc::EPERM)
            } else {
                Ok(0)
            }
        }
    }
}
