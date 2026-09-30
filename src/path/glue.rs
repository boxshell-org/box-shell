//! Glue filesystem — port of path/glue.c.  When a binding's guest path can't
//! exist in the guest rootfs, intermediate components are created in a temp
//! rootfs ("glue") with a covering binding.

use std::rc::Rc;

use crate::PATH_MAX;
use crate::fpath::FixedPath;
use crate::path::{Comparison, Finality, binding, compare_paths};
use crate::tracee::Tracee;

/// `build_glue()` — returns the type (mode & S_IFMT) of the component, 0 on
/// error.
pub fn build_glue(
    tracee: &mut Tracee,
    guest_path: &FixedPath,
    host_path: &mut FixedPath,
    finality: Finality,
) -> u32 {
    debug_assert!(tracee.glue_type != 0);

    if tracee.glue.is_none() {
        match crate::path::temp::create_temp_directory(None, "proot") {
            Some(dir) => tracee.glue = Some(Rc::new(dir)),
            None => {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::Internal,
                    "can't create glue rootfs"
                );
                return 0;
            }
        }
    }
    let glue = tracee.glue.as_ref().unwrap().clone();

    let comparison = compare_paths(glue.as_bytes(), host_path.as_bytes());
    let belongs_to_gluefs =
        comparison == Comparison::PathsAreEqual || comparison == Comparison::Path1IsPrefix;

    let (typ, mode) = if finality.is_final() {
        // Type propagated from initialize_binding().
        (tracee.glue_type, if belongs_to_gluefs { 0o777 } else { 0 })
    } else {
        (libc::S_IFDIR, 0o777)
    };

    let skip_create = std::env::var_os("PROOT_DONT_POLLUTE_ROOTFS").is_some() && !belongs_to_gluefs;

    if !skip_create {
        let c = std::ffi::CString::new(host_path.as_bytes()).unwrap();
        let status = if (typ & libc::S_IFMT) == libc::S_IFDIR {
            crate::sys::mkdir(&c, mode)
        } else {
            crate::sys::mknod(&c, mode | typ, 0)
        };
        // Remove guest-rootfs placeholders on termination.
        if status >= 0 && !belongs_to_gluefs {
            crate::path::temp::set_placeholder_destructor(host_path);
        }

        if status >= 0 || crate::sys::errno() == libc::EEXIST || finality.is_final() {
            return typ;
        }

        if belongs_to_gluefs {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "mkdir/mknod"
            );
            return 0;
        }
    }

    if glue.len() >= PATH_MAX - 1 || guest_path.len() >= PATH_MAX - 1 {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::Internal,
            "installing the binding: guest path too long"
        );
        return 0;
    }

    // From the example, create the binding "/black" -> "$GLUE".
    if binding::insort_binding3(tracee, glue.as_bytes(), guest_path.as_bytes()).is_none() {
        return 0;
    }

    typ
}
