//! Unix-socket path translation — port of syscall/socket.c.
//!
//! `sockaddr_un` has the same layout on every architecture.

use crate::Word;
use crate::fpath::FixedPath;
use crate::tracee::Tracee;
use crate::tracee::mem::{alloc_mem, peek_int32, poke_int32, read_data, write_data};

const OFFSETOF_PATH: usize = std::mem::offset_of!(libc::sockaddr_un, sun_path);
const SIZEOF_PATH: usize = 108; // sizeof(sun_path)
const SIZEOF_SOCKADDR_UN: usize = size_of::<libc::sockaddr_un>();

/// `read_sockaddr_un()` — copy the sockaddr_un at @address out of the
/// tracee; 1 if it's a named AF_UNIX socket, 0 if not applicable,
/// -errno on error.
fn read_sockaddr_un(
    tracee: &Tracee,
    sockaddr: &mut libc::sockaddr_un,
    max_size: Word,
    path: &mut FixedPath,
    address: Word,
    size: i32,
) -> i32 {
    debug_assert!(max_size <= SIZEOF_SOCKADDR_UN as Word);

    if size <= OFFSETOF_PATH as i32 || size as Word > max_size {
        return 0;
    }

    *sockaddr = crate::sys::zeroed();
    let raw = crate::sys::as_bytes_mut(sockaddr);
    let status = read_data(tracee, &mut raw[..size as usize], address);
    if status < 0 {
        return status;
    }

    if sockaddr.sun_family != libc::AF_UNIX as u16 || sockaddr.sun_path[0] == 0 {
        return 0;
    }

    // sun_path doesn't have to be NUL-terminated.
    let sun: &[u8] = crate::sys::as_bytes(&sockaddr.sun_path);
    let end = sun.iter().position(|&c| c == 0).unwrap_or(SIZEOF_PATH);
    let mut p = [0u8; crate::PATH_MAX];
    p[..end].copy_from_slice(&sun[..end]);
    path.set(&p[..end]);
    1
}

/// `translate_socketcall_enter()` — translate the sun_path at @*address
/// and move the rewritten sockaddr to tracer-allocated memory.
/// Returns 1 when a translation happened, 0 when not applicable,
/// -errno on error.
pub fn translate_socketcall_enter(tracee: &mut Tracee, address: &mut Word, size: Word) -> i32 {
    let mut sockaddr: libc::sockaddr_un = crate::sys::zeroed();
    let mut user_path = FixedPath::new();
    let mut host_path = FixedPath::new();

    if *address == 0 {
        return 0;
    }

    let status = read_sockaddr_un(
        tracee,
        &mut sockaddr,
        SIZEOF_SOCKADDR_UN as Word,
        &mut user_path,
        *address,
        size as i32,
    );
    if status <= 0 {
        return status;
    }

    let status = match crate::path::translate_path(
        tracee,
        &mut host_path,
        libc::AT_FDCWD,
        user_path.as_bytes(),
        true,
    ) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if status < 0 {
        return status;
    }

    if host_path.len() > SIZEOF_PATH {
        // The translated path doesn't fit: bind it to a short temp path.
        let shorter = match crate::path::temp::create_temp_name("proot") {
            Some(s) => s,
            None => return -libc::EINVAL,
        };
        if shorter.len() > SIZEOF_PATH {
            return -libc::EINVAL;
        }

        // The guest side of the new binding must be canonicalized.
        let mut guest = host_path.clone();
        if crate::path::detranslate_path(tracee, &mut guest, None).is_err() {
            return -libc::EINVAL;
        }

        if crate::path::binding::insort_binding3(tracee, shorter.as_bytes(), guest.as_bytes())
            .is_none()
        {
            return -libc::EINVAL;
        }

        host_path.set(shorter.as_bytes());
    }

    // Copy host_path into sun_path (not NUL-terminated if it fills).
    let hb = host_path.as_bytes();
    let n = hb.len().min(SIZEOF_PATH);
    for (dst, src) in sockaddr.sun_path.iter_mut().zip(hb.iter().take(n)) {
        *dst = *src as libc::c_char;
    }
    if n < SIZEOF_PATH {
        sockaddr.sun_path[n] = 0;
    }

    *address = alloc_mem(tracee, SIZEOF_SOCKADDR_UN as i64);
    if *address == 0 {
        return -libc::EFAULT;
    }

    let raw = crate::sys::as_bytes(&sockaddr);
    let status = write_data(tracee, *address, raw);
    if status < 0 {
        return status;
    }
    1
}

/// `translate_socketcall_exit()` — detranslate the sun_path written by
/// the kernel into the tracee's buffer.
pub fn translate_socketcall_exit(
    tracee: &mut Tracee,
    sock_addr: Word,
    size_addr: Word,
    max_size: Word,
) -> i32 {
    let mut sockaddr: libc::sockaddr_un = crate::sys::zeroed();
    let mut path = FixedPath::new();

    if sock_addr == 0 {
        return 0;
    }

    crate::sys::clear_errno();
    let mut size = peek_int32(tracee, size_addr);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }

    let max_size = max_size.min(SIZEOF_SOCKADDR_UN as Word);
    let status = read_sockaddr_un(tracee, &mut sockaddr, max_size, &mut path, sock_addr, size);
    if status <= 0 {
        return status;
    }

    if let Err(e) = crate::path::detranslate_path(tracee, &mut path, None) {
        return e;
    }

    let mut is_truncated = false;
    size = (OFFSETOF_PATH + path.len() + 1) as i32;
    if size < 0 || size as Word > max_size {
        size = max_size as i32;
        is_truncated = true;
    }

    let pb = path.as_bytes();
    let n = pb.len().min(SIZEOF_PATH - 1);
    for (dst, src) in sockaddr.sun_path.iter_mut().zip(pb.iter().take(n)) {
        *dst = *src as libc::c_char;
    }
    sockaddr.sun_path[n] = 0;

    let raw = crate::sys::as_bytes(&sockaddr);
    let status = write_data(tracee, sock_addr, &raw[..size as usize]);
    if status < 0 {
        return status;
    }

    // If the sockaddr was truncated, addrlen reports one byte more than
    // was supplied (see accept(2)).
    if is_truncated {
        size = max_size as i32 + 1;
    }

    crate::sys::clear_errno();
    poke_int32(tracee, size_addr, size);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }
    0
}
