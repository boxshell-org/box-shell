//! `#!` interpreter-script expansion — port of execve/shebang.c.

use std::os::unix::ffi::OsStrExt;

use crate::execve::aoxp::{
    XPointerArray, fetch_array_of_xpointers, push_array_of_xpointers, resize_array_of_xpointers,
    write_xpointees,
};
use crate::fpath::FixedPath;
use crate::tracee::Tracee;
use crate::tracee::reg::{Reg, sysarg};

/// `BINPRM_BUF_SIZE` (linux/binfmts.h).
const BINPRM_BUF_SIZE: usize = 256;

/// Maximum recursion when a script's interpreter is itself a script.
/// (`MAXSYMLINKS` in the C code.)
const MAX_SHEBANG_DEPTH: usize = 40;

/// `translate_and_check_exec()` — canonicalize `user_path` into `host_path`,
/// then verify it exists, is executable and is a regular file.
pub fn translate_and_check_exec(
    tracee: &mut Tracee,
    host_path: &mut FixedPath,
    user_path: &[u8],
) -> i32 {
    if user_path.is_empty() {
        return -libc::ENOEXEC;
    }
    if let Err(e) = crate::path::translate_path(tracee, host_path, libc::AT_FDCWD, user_path, true)
    {
        return e;
    }
    let c = match std::ffi::CString::new(host_path.as_bytes()) {
        Ok(c) => c,
        Err(_) => return -libc::EINVAL,
    };
    if crate::sys::access(&c, libc::F_OK) < 0 {
        return -libc::ENOENT;
    }
    if crate::sys::access(&c, libc::X_OK) < 0 {
        return -libc::EACCES;
    }
    if crate::sys::lstat(&c).is_err() {
        return -libc::EPERM;
    }
    0
}

/// `#!interpreter [arg]` split result: `Ok(None)` = not a script,
/// `Ok(Some((interp, arg)))` = shebang found, `Err(-errno)` = I/O failure.
type Shebang = Result<Option<(Vec<u8>, Vec<u8>)>, i32>;

/// `extract_shebang()` — read the `#!interpreter [arg]` line of `host_path`.
fn extract_shebang(host_path: &[u8]) -> Shebang {
    let c = std::ffi::CString::new(host_path).map_err(|_| -libc::EINVAL)?;
    let fd = crate::sys::open(&c, libc::O_RDONLY, 0);
    if fd < 0 {
        return Err(-crate::sys::errno());
    }
    let result = extract_shebang_fd(fd);
    crate::sys::close(fd);
    result
}

fn extract_shebang_fd(fd: i32) -> Shebang {
    let read1 = |fd: i32| -> Result<u8, i32> {
        let mut b = [0u8; 1];
        let n = crate::sys::read(fd, &mut b);
        if n < 0 {
            Err(-crate::path::errno())
        } else if n == 0 {
            Err(0) // sentinel: EOF
        } else {
            Ok(b[0])
        }
    };

    // Read "#!".
    let mut magic = [0u8; 2];
    let n = crate::sys::read(fd, &mut magic);
    if n < 0 {
        return Err(-crate::path::errno());
    }
    if n < 2 || magic[0] != b'#' || magic[1] != b'!' {
        return Ok(None);
    }
    let mut current_length = 2usize;

    let mut user_path: Vec<u8> = Vec::new();
    let mut argument: Vec<u8> = Vec::new();

    // Skip leading blanks.
    let mut tmp = loop {
        match read1(fd) {
            Err(0) => return Err(-libc::ENOEXEC),
            Err(e) => return Err(e),
            Ok(b) => {
                current_length += 1;
                if (b != b' ' && b != b'\t') || current_length >= BINPRM_BUF_SIZE {
                    break b;
                }
            }
        }
    };

    // Slurp the interpreter path until space/EOL.  A '\0' marker inside
    // user_path records where the name ended once an argument starts.
    let mut i = 0usize;
    let mut done = false;
    while current_length < BINPRM_BUF_SIZE {
        match tmp {
            b' ' | b'\t' => user_path.push(0),
            b'\n' | b'\r' => {
                done = true;
                break;
            }
            _ => {
                if i > 1 && user_path.last() == Some(&0) {
                    // Argument begins.
                    break;
                }
                user_path.push(tmp);
            }
        }
        match read1(fd) {
            Err(0) => {
                done = true;
                break;
            }
            Err(e) => return Err(e),
            Ok(b) => {
                tmp = b;
                current_length += 1;
                i += 1;
            }
        }
    }
    if done || current_length >= BINPRM_BUF_SIZE {
        strip_nul(&mut user_path);
        return Ok(Some((user_path, argument)));
    }

    // The interpreter name ends at the first NUL marker; the rest is argument.
    if let Some(nul) = user_path.iter().position(|b| *b == 0) {
        user_path.truncate(nul);
    }

    // Slurp the argument until EOL.
    let mut i = 0usize;
    while current_length < BINPRM_BUF_SIZE {
        if tmp == b'\n' || tmp == b'\r' {
            break;
        }
        argument.push(tmp);
        match read1(fd) {
            Err(0) => {
                strip_nul(&mut user_path);
                return Ok(Some((user_path, Vec::new())));
            }
            Err(e) => return Err(e),
            Ok(b) => {
                tmp = b;
                current_length += 1;
                i += 1;
            }
        }
    }
    let _ = i;
    // Remove trailing blanks.
    while argument.last().is_some_and(|b| *b == b' ' || *b == b'\t') {
        argument.pop();
    }
    strip_nul(&mut user_path);
    Ok(Some((user_path, argument)))
}

fn strip_nul(v: &mut Vec<u8>) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

/// `expand_shebang()` — if `user_path` is a script, rewrite the tracee's
/// argv so the interpreter gets `interp [arg] script orig_argv[1..]`.
/// Returns Ok(1) when a shebang was expanded, Ok(0) when none, Err(-errno).
pub fn expand_shebang(
    tracee: &mut Tracee,
    host_path: &mut FixedPath,
    user_path: &mut FixedPath,
) -> Result<i32, i32> {
    let mut argv: Option<XPointerArray> = None;
    let mut has_shebang = false;
    let mut no_more = false;

    for _ in 0..MAX_SHEBANG_DEPTH {
        // Translate + validate the current candidate.
        let status = translate_and_check_exec(tracee, host_path, user_path.as_bytes());
        if status < 0 {
            return Err(status);
        }
        let old_user_path = user_path.as_bytes().to_vec();

        match extract_shebang(host_path.as_bytes())? {
            None => {
                no_more = true;
                break;
            }
            Some((interp, argument)) => {
                has_shebang = true;
                user_path.set(&interp);

                // Translate + validate the interpreter itself.
                let status = translate_and_check_exec(tracee, host_path, user_path.as_bytes());
                if status < 0 {
                    return Err(status);
                }

                if argv.is_none() {
                    argv = Some(fetch_array_of_xpointers(tracee, sysarg(2), 0)?);
                }
                let argv = argv.as_mut().unwrap();
                let argc_one = (argv.entries.len() == 1) as isize;
                if !argument.is_empty() {
                    resize_array_of_xpointers(argv, 0, 2 + argc_one);
                    write_xpointees(argv, 0, &[&interp, &argument, &old_user_path]);
                } else {
                    resize_array_of_xpointers(argv, 0, 1 + argc_one);
                    write_xpointees(argv, 0, &[&interp, &old_user_path]);
                }
            }
        }
    }
    if !no_more {
        return Err(-libc::ELOOP);
    }
    if !has_shebang && argv.is_none() {
        return Ok(0);
    }

    if let Some(mut argv) = argv {
        let st = push_array_of_xpointers(tracee, &mut argv, Reg::Sysarg2);
        if st < 0 {
            return Err(st);
        }
    }
    Ok(if has_shebang { 1 } else { 0 })
}

/// Path OsStr → bytes helper (kept local for readability).
#[allow(dead_code)]
fn os_bytes(s: &std::ffi::OsStr) -> &[u8] {
    s.as_bytes()
}
