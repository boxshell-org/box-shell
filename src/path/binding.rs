//! Bindings — port of path/binding.c.
//!
//! A binding pairs a canonicalized host path with a canonicalized guest path.
//! Each tracee keeps three orderings of the same set: `pending` (as given by
//! the user, guest-ordered, not yet canonicalized), `guest` and `host` (both
//! canonicalized, ordered by their respective side).  `Vec<Rc<Binding>>`
//! replaces the C triple circular lists.

use std::rc::Rc;

use crate::fpath::FixedPath;
use crate::path::{compare_paths2, compare_paths, getcwd2, join_paths2, realpath2, Comparison, Side};
use crate::tracee::Tracee;

pub struct Binding {
    pub host: FixedPath,
    pub guest: FixedPath,
    pub need_substitution: bool,
}

impl Binding {
    pub fn path(&self, side: Side) -> &FixedPath {
        match side {
            Side::Host => &self.host,
            _ => &self.guest,
        }
    }
}



/// `get_binding()` — find the binding covering `path` on `side`.
pub fn get_binding(tracee: &Tracee, side: Side, path: &[u8]) -> Option<Rc<Binding>> {
    debug_assert!(path.first() == Some(&b'/'));
    let fs = tracee.fs.borrow();
    let list = match side {
        Side::Guest => &fs.guest,
        Side::Host => &fs.host,
        Side::Pending => &fs.pending,
    };
    for binding in list.iter() {
        let reference = binding.path(side);
        let cmp = compare_paths2(reference.as_bytes(), path);
        if cmp != Comparison::PathsAreEqual && cmp != Comparison::Path1IsPrefix {
            continue;
        }
        // Avoid false positives when a prefix of the rootfs is used as an
        // asymmetric binding (e.g. `-b /usr:/x` with rootfs under /usr).
        if side == Side::Host
            && compare_paths(get_root(tracee).as_bytes(), b"/") != Comparison::PathsAreEqual
            && crate::path::belongs_to_guestfs(tracee, path)
        {
            continue;
        }
        return Some(binding.clone());
    }
    None
}

/// `get_path_binding()` — the side-specific path of the matching binding.
pub fn get_path_binding(tracee: &Tracee, side: Side, path: &[u8]) -> Option<FixedPath> {
    get_binding(tracee, side, path).map(|b| b.path(side).clone())
}

/// `get_root()` — host path of the binding mounted at guest "/".
pub fn get_root(tracee: &Tracee) -> FixedPath {
    let fs = tracee.fs.borrow();
    if fs.guest.is_empty() {
        if fs.pending.is_empty() {
            return FixedPath::new();
        }
        let b = fs.pending.last().unwrap();
        if compare_paths(b.guest.as_bytes(), b"/") != Comparison::PathsAreEqual {
            return FixedPath::new();
        }
        return b.host.clone();
    }
    fs.guest.last().unwrap().host.clone()
}

/// `substitute_binding()` — replace the `side` prefix of `path` with the
/// binding's other side.
///
/// Returns Ok(0) for symmetric bindings, Ok(1) after substitution,
/// Err(-ENOENT) when no binding covers `path`.
pub fn substitute_binding(tracee: &Tracee, side: Side, path: &mut FixedPath) -> Result<i32, i32> {
    let binding = match get_binding(tracee, side, path.as_bytes()) {
        Some(b) => b,
        None => return Err(-libc::ENOENT),
    };
    if !binding.need_substitution {
        return Ok(0);
    }
    let (reference, reverse) = match side {
        Side::Guest => (&binding.guest, &binding.host),
        Side::Host => (&binding.host, &binding.guest),
        Side::Pending => return Err(-libc::EACCES),
    };
    path.substitute_prefix(reference.len(), reverse.as_bytes())?;
    Ok(1)
}

/// `insort_binding()` — insert `binding` into `side`'s list, preserving the
/// nested-binding order.  On an exact-path conflict in the guest list the old
/// binding is replaced and unlinked from all lists.
fn insort_binding(tracee: &Tracee, side: Side, binding: Rc<Binding>) {
    let mut fs = tracee.fs.borrow_mut();
    let list: &mut Vec<Rc<Binding>> = match side {
        Side::Pending => &mut fs.pending,
        Side::Guest => &mut fs.guest,
        Side::Host => &mut fs.host,
    };

    let binding_path = binding.path(side);
    let mut previous: Option<usize> = None;
    let mut next: Option<usize> = None;
    let mut replaced: Option<(usize, Rc<Binding>)> = None;

    for (i, iter) in list.iter().enumerate() {
        let iterator_path = iter.path(side);
        match compare_paths2(binding_path.as_bytes(), iterator_path.as_bytes()) {
            Comparison::PathsAreEqual => {
                if side == Side::Host {
                    previous = Some(i);
                    continue;
                }
                if tracee.verbose > 0
                    && std::env::var_os("PROOT_IGNORE_MISSING_BINDINGS").is_none()
                {
                    crate::note!(
                        crate::note::Severity::Warning,
                        crate::note::Origin::User,
                        "both '{}' and '{}' are bound to '{}', only the last binding is active.",
                        iter.host,
                        binding.host,
                        binding.guest
                    );
                }
                replaced = Some((i, iter.clone()));
                break;
            }
            Comparison::Path1IsPrefix => previous = Some(i),
            Comparison::Path2IsPrefix => {
                if next.is_none() {
                    next = Some(i);
                }
            }
            Comparison::PathsAreNotComparable => {}
        }
    }

    if let Some((i, removed)) = replaced {
        list.insert(i + 1, binding);
        list.remove(i);
        // Unlink the replaced binding from the other lists too.
        fs.host.retain(|b| !Rc::ptr_eq(b, &removed));
        fs.pending.retain(|b| !Rc::ptr_eq(b, &removed));
        return;
    }
    if let Some(p) = previous {
        list.insert(p + 1, binding);
    } else if let Some(n) = next {
        list.insert(n, binding);
    } else {
        list.insert(0, binding);
    }
}

/// `insort_binding2` — set need_substitution and insert into guest+host lists.
pub fn insort_binding2(tracee: &Tracee, binding: &mut Binding) -> Rc<Binding> {
    binding.need_substitution =
        compare_paths(binding.host.as_bytes(), binding.guest.as_bytes()) != Comparison::PathsAreEqual;
    let rc = Rc::new(std::mem::replace(
        binding,
        Binding {
            host: FixedPath::new(),
            guest: FixedPath::new(),
            need_substitution: false,
        },
    ));
    insort_binding(tracee, Side::Guest, rc.clone());
    insort_binding(tracee, Side::Host, rc.clone());
    rc
}

/// `insort_binding3` — allocate + insert `host_path:guest_path`.
pub fn insort_binding3(tracee: &Tracee, host_path: &[u8], guest_path: &[u8]) -> Option<Rc<Binding>> {
    let mut b = Binding {
        host: FixedPath::from_bytes(host_path),
        guest: FixedPath::from_bytes(guest_path),
        need_substitution: false,
    };
    if b.host.len() >= crate::PATH_MAX - 1 || b.guest.len() >= crate::PATH_MAX - 1 {
        return None;
    }
    Some(insort_binding2(tracee, &mut b))
}

/// `new_binding()` — add a pending binding `host:guest` (guest defaults to
/// host when None).  `must_exist` controls whether a missing host path is an
/// error.
pub fn new_binding(
    tracee: &mut Tracee,
    host: &[u8],
    guest: Option<&[u8]>,
    must_exist: bool,
) -> Option<Rc<Binding>> {
    let ignore_missing = std::env::var_os("PROOT_IGNORE_MISSING_BINDINGS").is_some();
    let mut binding = Binding {
        host: FixedPath::new(),
        guest: FixedPath::new(),
        need_substitution: false,
    };

    // /proc/self/... stays symbolic: "self" must resolve against the *calling*
    // tracee at syscall time, not against proot at init time.
    let host_str = host;
    if host_str.starts_with(b"/proc/self")
        && (host_str.get(10) == Some(&b'/') || host_str.len() == 10)
    {
        if host_str.len() + 1 >= crate::PATH_MAX {
            if must_exist && !ignore_missing {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "can't sanitize binding \"{}\": {}",
                    String::from_utf8_lossy(host),
                    io_error_string(libc::ENAMETOOLONG)
                );
            }
            return None;
        }
        binding.host.set(host);
    } else {
        // During a sub-reconfiguration the path would be canonicalized in
        // the reconfigured tracee's namespace; that hook is wired up with the
        // -r/-R CLI handling.
        let status = realpath2(None, &mut binding.host, host, true);
        if let Err(e) = status {
            if must_exist && !ignore_missing {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "can't sanitize binding \"{}\": {}",
                    String::from_utf8_lossy(host),
                    io_error_string(-e)
                );
            }
            return None;
        }
    }

    let guest = guest.unwrap_or(host);
    if guest.first() != Some(&b'/') {
        let mut base = FixedPath::new();
        if getcwd2(None, &mut base).is_err() {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::Internal,
                "can't sanitize binding"
            );
            return None;
        }
        if join_paths2(&mut binding.guest, base.as_bytes(), guest).is_err() {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "can't sanitize binding \"{}\"",
                String::from_utf8_lossy(guest)
            );
            return None;
        }
    } else {
        binding.guest.set(guest);
    }

    let rc = Rc::new(binding);
    insort_binding(tracee, Side::Pending, rc.clone());
    Some(rc)
}

pub fn io_error_string(errno: i32) -> String {
    crate::strerror(errno)
}

/// `remove_binding_from_all_lists()` — drop a binding from every list of
/// every tracee sharing this file-system namespace (guest, host, pending).
pub fn remove_binding_from_all_lists(tracee: &Tracee, binding: &Rc<Binding>) {
    let target = Rc::as_ptr(binding) as usize;
    let mut fs = tracee.fs.borrow_mut();
    fs.guest.retain(|b| Rc::as_ptr(b) as usize != target);
    fs.host.retain(|b| Rc::as_ptr(b) as usize != target);
    fs.pending.retain(|b| Rc::as_ptr(b) as usize != target);
}

/// `initialize_binding()` — canonicalize the guest side and promote the
/// binding into the guest+host lists.
pub fn initialize_binding(tracee: &mut Tracee, binding: &Rc<Binding>) {
    if compare_paths(binding.guest.as_bytes(), b"/") != Comparison::PathsAreEqual {
        let mut path = binding.guest.clone();
        // Does the user explicitly tell not to dereference the guest path?
        let mut dereference = true;
        if path.as_bytes().last() == Some(&b'!') {
            path.truncate(path.len() - 1);
            dereference = false;
        }

        // Remember the type of the final component for build_glue().
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let c = std::ffi::CString::new(binding.host.as_bytes()).unwrap();
        let status = unsafe { libc::lstat(c.as_ptr(), &mut st) };
        tracee.glue_type = if status < 0
            || (st.st_mode & libc::S_IFMT) == libc::S_IFBLK
            || (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
            || (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
        {
            libc::S_IFREG
        } else {
            st.st_mode & libc::S_IFMT
        };

        // When the source is a directory and the target is a symlink, the
        // tracee must see a directory at the literal target path.
        if status >= 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            dereference = false;
        }

        let mut new_guest = FixedPath::from_bytes(b"/");
        match crate::path::canon::canonicalize(
            tracee,
            path.as_bytes(),
            dereference,
            &mut new_guest,
            0,
        ) {
            Ok(()) => {
                new_guest.chop_finality();
                // Replace binding.guest (Rc -> get_mut; only owner is us here
                // before insertion).
                let mut updated = Binding {
                    host: binding.host.clone(),
                    guest: new_guest,
                    need_substitution: binding.need_substitution,
                };
                updated.need_substitution = compare_paths(
                    updated.host.as_bytes(),
                    updated.guest.as_bytes(),
                ) != Comparison::PathsAreEqual;
                insort_binding2(tracee, &mut updated);
            }
            Err(e) => {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "sanitizing the guest path (binding) \"{}\": {}",
                    path,
                    io_error_string(-e)
                );
            }
        }
        tracee.glue_type = 0;
    } else {
        let mut updated = Binding {
            host: binding.host.clone(),
            guest: binding.guest.clone(),
            need_substitution: binding.need_substitution,
        };
        updated.need_substitution = compare_paths(
            updated.host.as_bytes(),
            updated.guest.as_bytes(),
        ) != Comparison::PathsAreEqual;
        insort_binding2(tracee, &mut updated);
    }
}

/// `initialize_bindings()` — promote every pending binding, in reverse
/// order: the binding to "/" (the deepest in the pending list) goes first
/// since it bootstraps the canonicalization of all the others.
pub fn initialize_bindings(tracee: &mut Tracee) {
    let pending: Vec<Rc<Binding>> = tracee.fs.borrow().pending.clone();
    for b in pending.iter().rev() {
        initialize_binding(tracee, b);
        // TODO: add_induced_bindings() for sub-reconfiguration contexts.
    }
    tracee.fs.borrow_mut().pending.clear();
}
