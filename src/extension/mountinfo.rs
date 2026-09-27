//! mountinfo extension — port of extension/mountinfo/mountinfo.c.
//!
//! Redirects opens of `/proc/<pid>/mountinfo` to a synthesized file:
//! on Android (guest root under /data) it rewrites the /data line as
//! the "/" mount, and always appends fake mount entries for runtime
//! bindings created via emulated mount() calls.

use std::io::{BufRead, BufReader, Write};

use crate::Word;
use crate::extension::Event;
use crate::fpath::FixedPath;
use crate::path::{Comparison, compare_paths};
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::reg::{RegVersion, get_sysnum};

#[derive(Default)]
pub struct Mountinfo;

fn has_extra_bindings(target: &Tracee) -> bool {
    target
        .fs
        .borrow()
        .guest
        .iter()
        .any(|b| b.guest.as_bytes() != b"/")
}

/// `mountinfo_check_open_path()` — if the translated path is
/// `/proc/<pid>/mountinfo`, generate the fake file and rewrite `path`.
fn check_open_path(tracee: &mut Tracee, path: &mut FixedPath) {
    let p = path.as_bytes();
    if !(p.len() > 16 && p.starts_with(b"/proc/") && p.ends_with(b"/mountinfo")) {
        return;
    }
    let pid_field = &p[6..p.len() - 10];
    if pid_field.is_empty() || !pid_field.iter().all(|c| c.is_ascii_digit()) {
        return;
    }
    let target_pid: i32 = match std::str::from_utf8(pid_field).unwrap().parse() {
        Ok(v) if v > 0 => v,
        _ => return,
    };
    let open_path = std::str::from_utf8(p).unwrap_or("").to_string();

    // The target may be the current tracee itself (already borrowed) —
    // use it directly in that case, like the C raw-pointer code.
    let mut root_path = FixedPath::new();
    let extra_bindings: bool;
    let guest_list: Vec<(Vec<u8>, Vec<u8>)>;
    if target_pid == tracee.pid {
        let _ = crate::path::translate_path(tracee, &mut root_path, libc::AT_FDCWD, b"/", true);
        extra_bindings = has_extra_bindings(tracee);
        guest_list = tracee
            .fs
            .borrow()
            .guest
            .iter()
            .map(|b| (b.guest.as_bytes().to_vec(), b.host.as_bytes().to_vec()))
            .collect();
    } else if let Some(rc) = crate::tracee::get_tracee(target_pid, false) {
        if let Ok(mut t) = rc.try_borrow_mut() {
            let _ = crate::path::translate_path(&mut t, &mut root_path, libc::AT_FDCWD, b"/", true);
            extra_bindings = has_extra_bindings(&t);
            guest_list =
                t.fs.borrow()
                    .guest
                    .iter()
                    .map(|b| (b.guest.as_bytes().to_vec(), b.host.as_bytes().to_vec()))
                    .collect();
        } else {
            return;
        }
    } else {
        return;
    }
    let _ = &extra_bindings;

    let is_android_data = matches!(
        compare_paths(root_path.as_bytes(), b"/data"),
        Comparison::Path2IsPrefix | Comparison::PathsAreEqual
    );
    if !is_android_data && !extra_bindings {
        return;
    }

    let real = match std::fs::File::open(&open_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let new_path = match crate::path::temp::create_temp_file("mountinfo") {
        Some(n) => n,
        None => return,
    };
    let mut out = match std::fs::File::create(&new_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let reader = BufReader::new(real);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let mut found_line = false;

    if is_android_data {
        // Find the /data root line; emit it with root column = "/".
        for line in &lines {
            // The 'root' column is the 4th space-separated field.
            let mut chunk = line.as_str();
            let mut ok = true;
            for _ in 0..3 {
                match chunk.find(' ') {
                    Some(i) => chunk = &chunk[i + 1..],
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                continue;
            }
            if let Some(end) = chunk.find(' ') {
                if &chunk[..end] == "/data" {
                    // Write the line keeping only "/" from root column.
                    let keep = &line[..line.len() - chunk.len()];
                    let _ = writeln!(out, "{} /{}", keep, &chunk[end + 1..]);
                    found_line = true;
                    break;
                }
            }
        }
        // Rescan and copy standard mounts verbatim.
        if found_line {
            for line in &lines {
                let mut chunk = line.as_str();
                let mut ok = true;
                for _ in 0..3 {
                    match chunk.find(' ') {
                        Some(i) => chunk = &chunk[i + 1..],
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                let root = match chunk.find(' ') {
                    Some(e) => &chunk[..e],
                    None => continue,
                };
                if root == "/dev"
                    || root.starts_with("/dev/")
                    || root == "/proc"
                    || root == "/sys"
                    || root.starts_with("/sys/")
                    || root == "/tmp"
                {
                    let _ = writeln!(out, "{}", line);
                }
            }
        }
    } else {
        for line in &lines {
            let _ = writeln!(out, "{}", line);
        }
        found_line = true;
    }

    // Append runtime bindings so sandbox helpers see their fake mounts.
    let mut next_id = 1_000_000u32;
    for (guest, host) in &guest_list {
        if guest == b"/" {
            continue;
        }
        let _ = writeln!(
            out,
            "{} 1 0:1 / {} rw,relatime - bind {} rw,relatime",
            next_id,
            String::from_utf8_lossy(guest),
            String::from_utf8_lossy(host),
        );
        next_id += 1;
    }
    drop(out);

    if found_line {
        path.set(new_path.as_bytes());
    }
}

impl Mountinfo {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::TranslatedPath { path } => {
                let num = get_sysnum(tracee, RegVersion::Original);
                if num == Sysnum::open || num == Sysnum::openat {
                    check_open_path(tracee, path);
                }
                0
            }
            _ => 0,
        }
    }
    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        &[]
    }
    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self
    }
}
