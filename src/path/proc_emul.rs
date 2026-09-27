//! /proc readlink emulation — port of path/proc.c.

use crate::fpath::FixedPath;
use crate::path::{compare_paths, Comparison};
use crate::tracee::Tracee;
use crate::PATH_MAX;

/// `Action` from proc.c.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Default,
    Canonicalize,
    DontCanonicalize,
}

/// `readlink_proc()` — emulate readlink("base/component") where base is under
/// /proc.  Returns Err(-errno) on error, Ok(action) otherwise; on
/// Canonicalize `result` holds the substituted path (nul handling via
/// FixedPath).
pub fn readlink_proc(
    tracee: &Tracee,
    result: &mut FixedPath,
    base: &FixedPath,
    component: &[u8],
    comparison: Comparison,
) -> Result<Action, i32> {
    match comparison {
        Comparison::PathsAreEqual => {
            // Substitute "/proc/self" with "/proc/<PID>".
            if component != b"self" {
                return Ok(Action::Default);
            }
            result.set(format!("/proc/{}", tracee.pid).as_bytes());
            return Ok(Action::Canonicalize);
        }
        Comparison::Path1IsPrefix => {}
        _ => return Ok(Action::Default),
    }

    // Normalize /proc/self/... to /proc/<pid>/... so bound paths like
    // "-b /proc/self/fd:/dev/fd" reach the fd handling below.
    let base_bytes: Vec<u8>;
    let tail = &base.as_bytes()[b"/proc/".len()..];
    let normalized: Vec<u8>;
    let base: &[u8] = if tail.starts_with(b"self")
        && (tail.len() == 4 || tail[4] == b'/')
    {
        normalized = format!("/proc/{}{}", tracee.pid, String::from_utf8_lossy(&tail[4..]))
            .into_bytes();
        &normalized
    } else {
        base.as_bytes()
    };

    let pid: i32 = atoi(&base[b"/proc/".len()..]);
    if pid == 0 {
        return Ok(Action::Default);
    }
    base_bytes = base.to_vec();
    let _ = base_bytes;

    // Handle links in "/proc/<PID>/".
    let proc_path = format!("/proc/{}", pid);
    let comparison = compare_paths(proc_path.as_bytes(), base);
    match comparison {
        Comparison::PathsAreEqual => {
            let known = crate::tracee::get_tracee(pid, false);
            let known = match known {
                Some(t) => t,
                None => return Ok(Action::Default),
            };
            let known = known.borrow();

            macro_rules! substitute {
                ($name:expr, $string:expr) => {
                    if component == $name {
                        let s: &[u8] = $string;
                        if s.len() >= PATH_MAX {
                            return Err(-libc::EPERM);
                        }
                        result.set(s);
                        return Ok(Action::Canonicalize);
                    }
                };
            }

            let exe_bytes = known.exe.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default();
            let cwd_bytes = known.fs.borrow().cwd.as_bytes().to_vec();
            let root_bytes = crate::path::binding::get_root(&known).as_bytes().to_vec();
            substitute!(b"exe", &exe_bytes);
            substitute!(b"cwd", &cwd_bytes);
            substitute!(b"root", &root_bytes);
            return Ok(Action::Default);
        }
        Comparison::Path1IsPrefix => {}
        _ => return Ok(Action::Default),
    }

    // Handle links in "/proc/<PID>/fd/".
    let proc_path = format!("/proc/{}/fd", pid);
    if compare_paths(proc_path.as_bytes(), base) == Comparison::PathsAreEqual {
        // Sanity check: a number is expected.
        let s = std::str::from_utf8(component).unwrap_or("");
        if s.parse::<i64>().is_err() || s.is_empty() {
            return Err(-libc::EPERM);
        }
        // Don't dereference: they can point to anonymous pipes/sockets.
        result.set(base);
        result.push_component(component)?;
        return Ok(Action::DontCanonicalize);
    }

    Ok(Action::Default)
}

/// `readlink_proc2()` — emulate readlink on `referer` (a strict /proc
/// subpath).  Returns Ok(len) when emulated, Ok(0) otherwise.
pub fn readlink_proc2(
    tracee: &Tracee,
    result: &mut FixedPath,
    referer: &FixedPath,
) -> Result<usize, i32> {
    if referer.len() >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    debug_assert!(compare_paths(b"/proc", referer.as_bytes()) == Comparison::Path1IsPrefix);

    let mut base = referer.clone();
    let pos = match base.as_bytes().iter().rposition(|&c| c == b'/') {
        Some(p) if p != 0 => p,
        _ => return Ok(0),
    };
    let component = base.as_bytes()[pos + 1..].to_vec();
    base.truncate(pos);
    if component.is_empty() {
        return Ok(0);
    }

    match readlink_proc(tracee, result, &base, &component, Comparison::Path1IsPrefix)? {
        Action::Canonicalize => Ok(result.len()),
        _ => Ok(0),
    }
}

/// atoi() semantics: parse leading decimal digits.
fn atoi(bytes: &[u8]) -> i32 {
    let mut v: i64 = 0;
    let mut neg = false;
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'-' {
        neg = true;
        i += 1;
    } else if i < bytes.len() && bytes[i] == b'+' {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        v = v * 10 + (bytes[i] - b'0') as i64;
        i += 1;
    }
    if neg {
        v = -v;
    }
    v as i32
}
