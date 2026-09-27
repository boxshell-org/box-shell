//! Shadow pipe read ends — port of syscall/pipe_shadow.c.
//!
//! When a tracee closes the read end of an anonymous pipe while a child
//! still holds the write end, ptrace serialization can make the parent
//! close first — the child's write() then gets EPIPE.  The tracer opens a
//! shadow read reference via /proc/<pid>/fd/<fd> and releases it once the
//! race window is over (POLLHUP, would-block writer, or max age).

const MAX_SHADOW_PIPES: usize = 32;
const SHADOW_MAX_AGE_MS: i64 = 1000;
const SHADOW_TIMER_MS: i64 = 50;
const SHADOW_REAP_INTERVAL_MS: i64 = SHADOW_TIMER_MS / 2;
const F_GETPIPE_SZ: i32 = 1032;

struct Shadow {
    fd: i32,
    birth: libc::timespec,
}

static mut SHADOWS: [Shadow; MAX_SHADOW_PIPES] = {
    const S: Shadow = Shadow {
        fd: -1,
        birth: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    [S; MAX_SHADOW_PIPES]
};
static mut SHADOWS_HELD: i32 = 0;
static mut LAST_REAP: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

fn elapsed_ms(since: &libc::timespec) -> i64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } < 0 {
        return 0;
    }
    (now.tv_sec - since.tv_sec) * 1000 + (now.tv_nsec - since.tv_nsec) / 1_000_000
}

/// `writer_would_block()` — the pipe is too full for a writer to proceed.
fn writer_would_block(fd: i32) -> bool {
    let capacity = unsafe { libc::fcntl(fd, F_GETPIPE_SZ) };
    if capacity <= 0 {
        return false;
    }
    let mut buffered: libc::c_int = 0;
    if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut buffered) } < 0 {
        return false;
    }
    buffered as i64
        > if capacity as i64 > libc::PIPE_BUF as i64 {
            capacity as i64 - libc::PIPE_BUF as i64
        } else {
            0
        }
}

/// `shadow_pipe_read_end()` — open a tracer-side read reference to the
/// tracee's pipe-read fd about to be closed.
pub fn shadow_pipe_read_end(tracee_pid: i32, tracee_fd: i32) {
    unsafe {
        // Anonymous pipe?
        let path = format!("/proc/{}/fd/{}", tracee_pid, tracee_fd);
        let link = match std::fs::read_link(&path) {
            Ok(l) => l,
            Err(_) => return,
        };
        if !link.as_os_str().as_encoded_bytes().starts_with(b"pipe:[") {
            return;
        }

        // Read end only (O_RDONLY in O_ACCMODE).
        let info =
            match std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", tracee_pid, tracee_fd)) {
                Ok(t) => t,
                Err(_) => return,
            };
        let mut flags: u64 = 1;
        for line in info.lines() {
            if let Some(v) = line.strip_prefix("flags:") {
                flags = u64::from_str_radix(v.trim(), 8).unwrap_or(1);
                break;
            }
        }
        if (flags & libc::O_ACCMODE as u64) != libc::O_RDONLY as u64 {
            return;
        }

        let slot = match (*std::ptr::addr_of!(SHADOWS))
            .iter()
            .position(|s| s.fd == -1)
        {
            Some(s) => s,
            None => return,
        };

        let c = std::ffi::CString::new(path).unwrap();
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return;
        }
        SHADOWS[slot].fd = fd;
        let _ = libc::clock_gettime(
            libc::CLOCK_MONOTONIC,
            &mut (*std::ptr::addr_of_mut!(SHADOWS))[slot].birth,
        );
        SHADOWS_HELD += 1;
    }
}

/// `shadow_pipes_reap()` — release shadows that can no longer help.
pub fn reap() {
    unsafe {
        if SHADOWS_HELD == 0 {
            return;
        }
        if elapsed_ms(&*std::ptr::addr_of!(LAST_REAP)) < SHADOW_REAP_INTERVAL_MS {
            return;
        }
        let _ = libc::clock_gettime(
            libc::CLOCK_MONOTONIC,
            &mut *std::ptr::addr_of_mut!(LAST_REAP),
        );

        for shadow in (*std::ptr::addr_of_mut!(SHADOWS)).iter_mut() {
            if shadow.fd < 0 {
                continue;
            }
            let mut pfd = libc::pollfd {
                fd: shadow.fd,
                events: 0,
                revents: 0,
            };
            let hup = libc::poll(&mut pfd, 1, 0) > 0 && (pfd.revents & libc::POLLHUP) != 0;
            if hup
                || writer_would_block(shadow.fd)
                || elapsed_ms(&shadow.birth) >= SHADOW_MAX_AGE_MS
            {
                libc::close(shadow.fd);
                shadow.fd = -1;
                SHADOWS_HELD -= 1;
            }
        }
    }
}

/// `shadow_pipes_held()`.
pub fn held() -> bool {
    unsafe { SHADOWS_HELD > 0 }
}

/// `shadow_pipes_set_timer()` — arm/disarm the SIGALRM wakeup.
pub fn set_timer(enabled: bool) {
    static mut ARMED: bool = false;
    unsafe {
        if !enabled && !ARMED {
            return;
        }
        let mut timer: libc::itimerval = std::mem::zeroed();
        if enabled {
            timer.it_value.tv_usec = SHADOW_TIMER_MS * 1000;
        }
        if libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()) < 0 {
            return;
        }
        ARMED = enabled;
    }
}
