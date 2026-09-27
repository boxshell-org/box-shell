//! Canonicalization engine — port of path/canon.c.

use crate::fpath::FixedPath;
use crate::path::binding::substitute_binding;
use crate::path::f2fs::should_skip_file_access_due_to_f2fs_bug;
use crate::path::proc_emul::{readlink_proc, Action};
use crate::path::{compare_paths, join_paths2, Comparison, Finality, Side};
use crate::tracee::Tracee;
use crate::{NAME_MAX, PATH_MAX};

const MAXSYMLINKS: u32 = 32;

/// `next_component()` — extract the next component from `cursor`, skipping
/// leading separators.  Returns (component, finality); `cursor` is advanced
/// past the component and any trailing separators.
fn next_component(cursor: &mut &[u8]) -> Result<(Vec<u8>, Finality), i32> {
    while cursor.first() == Some(&b'/') {
        *cursor = &cursor[1..];
    }
    let start = *cursor;
    let mut i = 0;
    while i < start.len() && start[i] != b'/' {
        i += 1;
    }
    if i >= NAME_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    let component = start[..i].to_vec();
    *cursor = &start[i..];
    let want_dir = cursor.first() == Some(&b'/');
    while cursor.first() == Some(&b'/') {
        *cursor = &cursor[1..];
    }
    if cursor.is_empty() {
        Ok((component, if want_dir { Finality::Slash } else { Finality::Normal }))
    } else {
        Ok((component, Finality::NotFinal))
    }
}

/// `substitute_binding_stat()` — substitute bindings into `host_path`, then
/// lstat().  Returns Ok(true) when it names a symlink.
fn substitute_binding_stat(
    tracee: &mut Tracee,
    finality: Finality,
    recursion_level: u32,
    guest_path: &FixedPath,
    host_path: &mut FixedPath,
) -> Result<bool, i32> {
    host_path.set(guest_path.as_bytes());
    substitute_binding(tracee, Side::Guest, host_path)?;

    // Don't notify extensions during the initialization of a binding.
    if tracee.glue_type == 0 {
        let status = crate::extension::notify_host_path(
            tracee,
            host_path,
            finality.is_final() && recursion_level == 0,
        );
        if status < 0 {
            return Err(status);
        }
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let status;
    if should_skip_file_access_due_to_f2fs_bug(tracee, host_path.as_bytes()) {
        status = -1;
        unsafe { *libc::__errno_location() = libc::ENOENT };
    } else {
        let c = std::ffi::CString::new(host_path.as_bytes()).map_err(|_| -libc::EINVAL)?;
        status = unsafe { libc::lstat(c.as_ptr(), &mut st) };
        // /linkerconfig exists on Android but cannot be stat'ed.
        if status < 0
            && crate::path::errno() == libc::EACCES
            && host_path.as_bytes() == b"/linkerconfig"
        {
            st.st_mode = libc::S_IFDIR;
        }
    }

    // Build the glue between hostfs and guestfs during binding init.
    if status < 0 && tracee.glue_type != 0 {
        let mode = crate::path::glue::build_glue(tracee, guest_path, host_path, finality);
        if mode == 0 {
            st.st_mode = 0;
        } else {
            st.st_mode = mode;
        }
    }

    if !finality.is_final()
        && (st.st_mode & libc::S_IFMT) != libc::S_IFDIR
        && (st.st_mode & libc::S_IFMT) != libc::S_IFLNK
    {
        return Err(if status < 0 { -libc::ENOENT } else { -libc::ENOTDIR });
    }

    Ok((st.st_mode & libc::S_IFMT) == libc::S_IFLNK)
}

/// `canonicalize()` — like realpath(3) in the guest namespace: resolve
/// `user_path` (relative to the seeded `guest_path`, or absolute) into a
/// canonical guest path.  A final symlink is followed only when
/// `deref_final`.
pub fn canonicalize(
    tracee: &mut Tracee,
    user_path: &[u8],
    deref_final: bool,
    guest_path: &mut FixedPath,
    recursion_level: u32,
) -> Result<(), i32> {
    let mut symlinks_followed = 0u32;

    if recursion_level > MAXSYMLINKS {
        return Err(-libc::ELOOP);
    }
    if guest_path.len() >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    if user_path.first() != Some(&b'/') {
        if guest_path.as_bytes().first() != Some(&b'/') {
            return Err(-libc::EINVAL);
        }
    } else {
        guest_path.set(b"/");
    }

    let mut cursor: &[u8] = user_path;
    let mut finality = Finality::NotFinal;
    while !finality.is_final() {
        let (component, f) = next_component(&mut cursor)?;
        finality = f;

        if component == b"." {
            if finality.is_final() {
                finality = Finality::Dot;
            }
            continue;
        }
        if component == b".." {
            guest_path.pop_component();
            if finality.is_final() {
                finality = Finality::Slash;
            }
            continue;
        }

        let mut scratch_path = FixedPath::new();
        join_paths2(&mut scratch_path, guest_path.as_bytes(), &component)?;

        let mut host_path = FixedPath::new();
        let is_link = substitute_binding_stat(
            tracee,
            finality,
            recursion_level,
            &scratch_path,
            &mut host_path,
        )?;

        // Nothing special unless it's a link we must dereference.
        if !is_link || (finality == Finality::Normal && !deref_final) {
            let gp = guest_path.clone();
            join_paths2(guest_path, gp.as_bytes(), &component)?;
            continue;
        }

        // It's a link: dereference *and* canonicalize so it can't escape the
        // new root.
        let mut canonicalize_now = false;
        {
            let mut proc_base = guest_path.clone();
            let mut comparison = compare_paths(b"/proc", guest_path.as_bytes());
            if comparison != Comparison::PathsAreEqual && comparison != Comparison::Path1IsPrefix
            {
                // Check whether guest_path aliases /proc via a binding.
                let mut alias_base = guest_path.clone();
                let _ = substitute_binding(tracee, Side::Guest, &mut alias_base);
                if alias_base.as_bytes() != guest_path.as_bytes() {
                    comparison = compare_paths(b"/proc", alias_base.as_bytes());
                    proc_base = alias_base;
                }
            }

            match comparison {
                Comparison::PathsAreEqual | Comparison::Path1IsPrefix => {
                    match readlink_proc(
                        tracee,
                        &mut scratch_path,
                        &proc_base,
                        &component,
                        comparison,
                    )? {
                        Action::Canonicalize => canonicalize_now = true,
                        Action::DontCanonicalize => {
                            if finality == Finality::Normal {
                                guest_path.set(scratch_path.as_bytes());
                                return Ok(());
                            }
                            // Otherwise fall through to the real readlink.
                        }
                        Action::Default => {}
                    }
                }
                _ => {}
            }
        }

        if !canonicalize_now {
            let mut buf = vec![0u8; PATH_MAX];
            let n = {
                let c = std::ffi::CString::new(host_path.as_bytes())
                    .map_err(|_| -libc::EINVAL)?;
                let r =
                    unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr() as *mut _, PATH_MAX) };
                if r < 0 {
                    return Err(-crate::path::errno());
                }
                if r as usize == PATH_MAX {
                    return Err(-libc::ENAMETOOLONG);
                }
                r as usize
            };
            buf.truncate(n);
            scratch_path.set(&buf);

            if tracee.glue_type == 0 {
                let status =
                    crate::extension::notify_symlink_deref(tracee, &host_path, &mut scratch_path);
                if status < 0 {
                    return Err(status);
                }
            }

            crate::path::detranslate_path(tracee, &mut scratch_path, Some(&host_path))?;
        }

        // 'canon': recursively canonicalize the referree, relative to
        // guest_path when not absolute.
        symlinks_followed += 1;
        canonicalize(
            tracee,
            scratch_path.as_bytes(),
            true,
            guest_path,
            recursion_level + symlinks_followed,
        )?;

        // A non-final canonicalized component must exist and be a directory.
        let mut hp = FixedPath::new();
        substitute_binding_stat(tracee, finality, recursion_level, guest_path, &mut hp)?;
    }

    if recursion_level == 0 {
        let gp = guest_path.clone();
        match finality {
            Finality::Normal => {}
            Finality::Slash => join_paths2(guest_path, gp.as_bytes(), b"")?,
            Finality::Dot => join_paths2(guest_path, gp.as_bytes(), b".")?,
            _ => return Err(-libc::EINVAL),
        }
    }

    Ok(())
}

/// `next_component` helper for callers (binding init etc.) that want the
/// final-component of a canonical path.
pub fn basename_component(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && path[start - 1] != b'/' {
        start -= 1;
    }
    &path[start..end]
}
