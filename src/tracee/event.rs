//! Event loop — port of tracee/event.c + the lifecycle parts of tracee.c
//! (launch_process, new_child/attach_child, adoption of unnamed children).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::sysnum::Sysnum;
use crate::tracee::reg::{fetch_regs, get_sysnum, peek_reg, Reg, RegVersion};
use crate::tracee::{get_tracee, is_in_sysenter, Seccomp, Sigstop, Tracee};
use crate::Word;

pub type TraceeRef = Rc<RefCell<Tracee>>;

/* ================================================================== */
/* Seccomp/kernel capability probing                                   */
/* ================================================================== */

#[derive(Copy, Clone, PartialEq, Eq)]
enum EventmsgState {
    Unknown,
    Reliable,
    Lost,
}

static mut SECCOMP_AFTER_PTRACE_ENTER: bool = false;
static mut SECCOMP_PTRACE_EVENT_SUPPORTED: bool = false;
static mut EVENTMSG_STATE: EventmsgState = EventmsgState::Unknown;
static mut SECCOMP_DETECTED: bool = false;
static mut SECCOMP_AFTER_PTRACE_ENTER_CHECKED: bool = false;
static mut DELIVER_SIGTRAP: bool = false;
static mut LAST_EXIT_STATUS: i32 = -1;

/// Whether the kernel is new enough to generate PTRACE_EVENT_SECCOMP stops.
fn kernel_supports_ptrace_event_seccomp() -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } < 0 {
        return true;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let mut it = release.split('.');
    let major: i32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: i32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    major > 3 || (major == 3 && minor >= 5)
}

pub fn seccomp_event_happens_after_enter_sigtrap() -> bool {
    unsafe { !SECCOMP_AFTER_PTRACE_ENTER }
}

pub fn seccomp_ptrace_event_is_supported() -> bool {
    unsafe { SECCOMP_PTRACE_EVENT_SUPPORTED }
}

/* ================================================================== */
/* Process launch                                                      */
/* ================================================================== */

/// `launch_process()` — fork a child that asks to be traced and execve()s
/// `tracee.exe`.
pub fn launch_process(tracee_rc: &TraceeRef, argv: &[String]) -> i32 {
    let exe = {
        let t = tracee_rc.borrow();
        t.exe.clone()
    };
    let exe = match exe {
        Some(e) => e,
        None => return -libc::ENOENT,
    };

    // TODO: mem_prepare_before_first_execve / list_open_fd (verbose).

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            crate::note!(
                crate::note::Severity::Error,
                crate::note::Origin::System,
                "fork()"
            );
            -crate::path::errno()
        }
        0 => {
            // Child: give the guest a sane SIGPIPE disposition, request
            // tracing, stop for the event loop, install the filter, exec.
            unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
            let status = unsafe {
                libc::ptrace(
                    crate::ptrace::ptc::PTRACE_TRACEME as u32,
                    0,
                    std::ptr::null::<u8>(),
                    0usize,
                )
            };
            if status < 0 {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::System,
                    "ptrace(TRACEME)"
                );
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };

            if std::env::var_os("PROOT_NO_SECCOMP").is_none() {
                let mut t = tracee_rc.borrow_mut();
                let _ = crate::syscall::seccomp::enable_syscall_filtering(&mut t);
            }

            let argv_c: Vec<std::ffi::CString> = if argv.is_empty() {
                vec![std::ffi::CString::new("-sh").unwrap()]
            } else {
                argv.iter()
                    .map(|a| std::ffi::CString::new(a.as_bytes()).unwrap())
                    .collect()
            };
            let mut argv_ptrs: Vec<*const libc::c_char> =
                argv_c.iter().map(|c| c.as_ptr()).collect();
            argv_ptrs.push(std::ptr::null());
            let exe_c = std::ffi::CString::new(exe.as_bytes()).unwrap();
            unsafe {
                libc::execvp(exe_c.as_ptr(), argv_ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        pid => {
            let old_key = {
                let mut t = tracee_rc.borrow_mut();
                let old_key = t.pid;
                t.pid = pid;
                old_key
            };
            crate::tracee::unregister(old_key);
            crate::tracee::register_existing(tracee_rc, pid);
            0
        }
    }
}

/* ================================================================== */
/* Event loop                                                          */
/* ================================================================== */

/// `event_loop()` — waitpid(-1, __WALL) + dispatch until no tracee is left.
/// Returns the exit status of the last terminated program.
pub fn event_loop() -> i32 {
    unsafe {
        libc::atexit(kill_all_tracees_atexit);
    }

    install_signal_handlers();

    loop {
        // The only safe place to free tracees.
        crate::tracee::free_terminated_tracees();

        // Reap shadow pipes; tick periodically while any is held.
        crate::syscall::pipe_shadow::reap();
        crate::syscall::pipe_shadow::set_timer(crate::syscall::pipe_shadow::held());

        let mut tracee_status: i32 = 0;
        let pid = unsafe { libc::waitpid(-1, &mut tracee_status, libc::__WALL) };
        crate::syscall::pipe_shadow::set_timer(false);
        if pid < 0 {
            let e = crate::path::errno();
            if e == libc::EINTR {
                continue;
            }
            if e != libc::ECHILD {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::System,
                    "waitpid()"
                );
                return libc::EXIT_FAILURE;
            }
            break;
        }

        let tracee_rc = match get_tracee(pid, true) {
            Some(t) => t,
            None => continue,
        };

        {
            let mut t = tracee_rc.borrow_mut();
            t.running = false;

            let status = crate::extension::notify(
                &mut t,
                &mut crate::extension::Event::NewStatus {
                    status: tracee_status,
                },
            );
            if status != 0 {
                continue;
            }
        }

        if tracee_rc.borrow().as_ptracee.ptracer != 0 {
            let keep_stopped = crate::ptrace::wait::handle_ptracee_event(&tracee_rc, tracee_status);
            if keep_stopped {
                continue;
            }
        }

        let signal = handle_tracee_event(&tracee_rc, tracee_status);
        drain_deferred_attaches();
        restart_tracee(&tracee_rc, signal);
    }

    unsafe { LAST_EXIT_STATUS }
}

/* ================================================================== */
/* Deferred child attach                                               */
/*                                                                     */
/* resolve_pending_child() runs while the parent's RefCell is still    */
/* mutably borrowed, so it can't re-enter attach_child() directly.     */
/* It enqueues the (parent, flags, child) triple here and the event    */
/* loop attaches the child once the borrow is released.                */
/* ================================================================== */

thread_local! {
    static DEFERRED_ATTACHES: RefCell<VecDeque<(i32, Word, i32)>> =
        const { RefCell::new(VecDeque::new()) };
}

fn defer_attach(parent_pid: i32, clone_flags: Word, child_pid: i32) {
    DEFERRED_ATTACHES.with(|q| {
        q.borrow_mut()
            .push_back((parent_pid, clone_flags, child_pid))
    });
}

fn drain_deferred_attaches() {
    loop {
        let next = DEFERRED_ATTACHES
            .try_with(|q| q.borrow_mut().pop_front())
            .ok()
            .flatten();
        let (parent_pid, clone_flags, child_pid) = match next {
            Some(v) => v,
            None => return,
        };
        if let Some(parent_rc) = get_tracee(parent_pid, false) {
            let _ = attach_child(&parent_rc, clone_flags, child_pid);
        }
    }
}

extern "C" fn kill_all_tracees_atexit() {
    crate::tracee::kill_all_tracees();
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigfillset(&mut sa.sa_mask);

        for signum in 1..libc::SIGRTMAX() {
            match signum {
                libc::SIGQUIT | libc::SIGILL | libc::SIGABRT | libc::SIGFPE | libc::SIGSEGV => {
                    sa.sa_sigaction = kill_all_tracees2 as *const () as usize;
                }
                libc::SIGUSR1 | libc::SIGUSR2 => {
                    // Was print_talloc_hierarchy; keep a cheap tracee dump.
                    sa.sa_sigaction = dump_tracees as *const () as usize;
                }
                libc::SIGCHLD
                | libc::SIGCONT
                | libc::SIGSTOP
                | libc::SIGTSTP
                | libc::SIGTTIN
                | libc::SIGTTOU => {
                    continue;
                }
                _ => {
                    sa.sa_sigaction = libc::SIG_IGN as usize;
                }
            }
            if libc::sigaction(signum, &sa, std::ptr::null_mut()) < 0
                && crate::path::errno() != libc::EINVAL
            {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::System,
                    "sigaction({})",
                    signum
                );
            }
        }

        // SIGALRM wakes the loop for shadow-pipe reaping: SA_RESTART must NOT
        // be set so waitpid(2) returns EINTR.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO;
        sa.sa_sigaction = wakeup_event_loop as *const () as usize;
        libc::sigfillset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
    }
}

extern "C" fn kill_all_tracees2(signum: i32, siginfo: *mut libc::siginfo_t, _u: *mut libc::c_void) {
    let si_pid = unsafe { (*siginfo).si_pid() };
    crate::note!(
        crate::note::Severity::Warning,
        crate::note::Origin::Internal,
        "signal {} received from process {}",
        signum,
        si_pid
    );
    crate::tracee::kill_all_tracees();
    if signum != libc::SIGQUIT {
        unsafe { libc::_exit(libc::EXIT_FAILURE) };
    }
}

extern "C" fn wakeup_event_loop(_s: i32, _i: *mut libc::siginfo_t, _u: *mut libc::c_void) {}

extern "C" fn dump_tracees(_s: i32, _i: *mut libc::siginfo_t, _u: *mut libc::c_void) {
    // Keep this signal-safe: it only wakes the loop; verbose state dumps go
    // through normal note() paths elsewhere.
}

/* ================================================================== */
/* Per-event dispatch                                                  */
/* ================================================================== */

/// `handle_tracee_event()` — compute the restart signal for this stop.
pub fn handle_tracee_event(tracee_rc: &TraceeRef, tracee_status: i32) -> i32 {
    unsafe {
        if !SECCOMP_AFTER_PTRACE_ENTER_CHECKED {
            SECCOMP_AFTER_PTRACE_ENTER = std::env::var_os("PROOT_ASSUME_NEW_SECCOMP").is_some();
            SECCOMP_AFTER_PTRACE_ENTER_CHECKED = true;
        }
    }

    let mut t = tracee_rc.borrow_mut();
    let tracee: &mut Tracee = &mut t;

    // With seccomp, most events restart with PTRACE_CONT; PTRACE_SYSCALL is
    // kept whenever a sysexit stage must be reached.
    let sysexit_necessary = tracee.sysexit_pending
        || tracee.chain.syscalls.is_some()
        || tracee.restore_original_regs_after_seccomp_event;
    if tracee.restart_how == 0 {
        if tracee.seccomp == Seccomp::Enabled && !sysexit_necessary {
            tracee.restart_how = crate::ptrace::ptc::PTRACE_CONT as i32;
        } else {
            tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
        }
    }

    let mut signal = 0i32;

    if libc::WIFEXITED(tracee_status) {
        unsafe { LAST_EXIT_STATUS = libc::WEXITSTATUS(tracee_status) };
        crate::verbose!(
            Some(tracee),
            1,
            "vpid {}: exited with status {}",
            tracee.vpid,
            libc::WEXITSTATUS(tracee_status)
        );
        let pid = tracee.pid;
        drop(t);
        crate::tracee::terminate_tracee(pid);
        return signal;
    } else if libc::WIFSIGNALED(tracee_status) {
        check_architecture(tracee);
        crate::verbose!(
            Some(tracee),
            if tracee.vpid != 1 { 1 } else { 0 },
            "vpid {}: terminated with signal {}",
            tracee.vpid,
            libc::WTERMSIG(tracee_status)
        );
        let pid = tracee.pid;
        drop(t);
        crate::tracee::terminate_tracee(pid);
        return signal;
    } else if libc::WIFSTOPPED(tracee_status) {
        // Don't use WSTOPSIG(): it clears the PTRACE_EVENT_* bits.
        signal = (tracee_status & 0xfff00) >> 8;

        match signal {
            libc::SIGTRAP => {
                let default_ptrace_options = crate::ptrace::ptc::PTRACE_O_TRACESYSGOOD
                    | crate::ptrace::ptc::PTRACE_O_TRACEFORK
                    | crate::ptrace::ptc::PTRACE_O_TRACEVFORK
                    | crate::ptrace::ptc::PTRACE_O_TRACEVFORKDONE
                    | crate::ptrace::ptc::PTRACE_O_TRACEEXEC
                    | crate::ptrace::ptc::PTRACE_O_TRACECLONE
                    | crate::ptrace::ptc::PTRACE_O_TRACEEXIT;

                if unsafe { DELIVER_SIGTRAP } {
                    // A later bare SIGTRAP is a real signal: deliver as-is.
                } else {
                    unsafe { DELIVER_SIGTRAP = true };
                    // Try to enable seccomp-accelerated event delivery.
                    let status = unsafe {
                        libc::ptrace(
                            crate::ptrace::ptc::PTRACE_SETOPTIONS as u32,
                            tracee.pid,
                            std::ptr::null::<u8>(),
                            (default_ptrace_options | crate::ptrace::ptc::PTRACE_O_TRACESECCOMP)
                                as usize,
                        )
                    };
                    if status < 0 {
                        let status = unsafe {
                            libc::ptrace(
                                crate::ptrace::ptc::PTRACE_SETOPTIONS as u32,
                                tracee.pid,
                                std::ptr::null::<u8>(),
                                default_ptrace_options as usize,
                            )
                        };
                        if status < 0 {
                            crate::note!(
                                crate::note::Severity::Error,
                                crate::note::Origin::System,
                                "ptrace(PTRACE_SETOPTIONS)"
                            );
                            std::process::exit(libc::EXIT_FAILURE);
                        }
                        unsafe { SECCOMP_PTRACE_EVENT_SUPPORTED = false };
                    } else {
                        unsafe {
                            SECCOMP_PTRACE_EVENT_SUPPORTED = kernel_supports_ptrace_event_seccomp()
                        };
                    }
                    signal = handle_sigtrap_syscall(tracee, &mut signal);
                }
            }
            s if s == libc::SIGTRAP | 0x80 => {
                signal = handle_sigtrap_syscall(tracee, &mut signal);
            }
            s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_SECCOMP << 8)
                || s == libc::SIGTRAP | (0x08 /* PTRACE_EVENT_SECCOMP2 */ << 8) =>
            {
                signal = handle_seccomp_stop(tracee, sysexit_necessary);
            }
            s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_VFORK << 8) => {
                tracee.as_ptracee.event4.proot.pending = false;
                drop(t);
                new_child(&tracee_rc, libc::CLONE_VFORK as Word);
                return 0;
            }
            s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_FORK << 8)
                || s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_CLONE << 8) =>
            {
                tracee.as_ptracee.event4.proot.pending = false;
                drop(t);
                new_child(&tracee_rc, 0);
                return 0;
            }
            s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_VFORK_DONE << 8)
                || s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_EXEC << 8)
                || s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_EXIT << 8) =>
            {
                signal = 0;
                if tracee.last_restart_how != 0 {
                    tracee.restart_how = tracee.last_restart_how;
                }
            }
            libc::SIGSTOP => {
                // Hold the tracee until its FORK/CLONE event arrived.
                if tracee.exe.is_none() {
                    tracee.sigstop = Sigstop::Pending;
                    signal = -1;
                    tracee.as_ptracee.event4.proot.pending = false;
                    drop(t);
                    adopt_held_children();
                    return signal;
                }
                // The first SIGSTOP only notifies the tracer.
                if tracee.sigstop == Sigstop::Ignored {
                    tracee.sigstop = Sigstop::Allowed;
                    signal = 0;
                }
            }
            libc::SIGSYS => {
                signal = handle_sigsys(tracee, signal);
            }
            _ => {
                // Deliver as-is unless a syscall chain is running.
                if tracee.chain.syscalls.is_some()
                    || tracee.restore_original_regs_after_seccomp_event
                {
                    crate::verbose!(
                        Some(tracee),
                        5,
                        "vpid {}: suppressing signal during chain signal={} prev={}",
                        tracee.vpid,
                        signal,
                        tracee.chain.suppressed_signal
                    );
                    tracee.chain.suppressed_signal = signal;
                    signal = 0;
                }
            }
        }
    }

    // Clear the pending event, if any.
    tracee.as_ptracee.event4.proot.pending = false;

    signal
}

/// Shared handling for SIGTRAP and SIGTRAP|0x80 (syscall stops).
/// The stop signal itself is swallowed (C does `signal = 0` in these cases);
/// only a suppressed chain signal may be redelivered.
fn handle_sigtrap_syscall(tracee: &mut Tracee, _signal: &mut i32) -> i32 {
    let mut signal = 0;

    if tracee.exe.is_none() {
        tracee.restart_how = crate::ptrace::ptc::PTRACE_CONT as i32;
        return 0;
    }

    match tracee.seccomp {
        Seccomp::Enabled => {
            if is_in_sysenter(tracee) {
                tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
                tracee.sysexit_pending = true;
            } else {
                tracee.restart_how = crate::ptrace::ptc::PTRACE_CONT as i32;
                tracee.sysexit_pending = false;
            }
            do_syscall_stage(tracee, &mut signal);
        }
        Seccomp::Disabled => {
            do_syscall_stage(tracee, &mut signal);
        }
        Seccomp::Disabling => {
            // Seccomp was disabled by the previous syscall but its sysenter
            // stage was already handled.
            tracee.seccomp = Seccomp::Disabled;
            if is_in_sysenter(tracee) {
                tracee.status = 1;
            }
        }
    }

    if tracee.seccomp == Seccomp::Disabling {
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
        tracee.seccomp = Seccomp::Disabled;
    }

    signal
}

fn do_syscall_stage(tracee: &mut Tracee, signal: &mut i32) {
    if !tracee.seccomp_already_handled_enter {
        let was_sysenter = is_in_sysenter(tracee);

        crate::syscall::translate_syscall(tracee);

        // The exit of a fork-like syscall whose event didn't name the child.
        if !was_sysenter && tracee.pending_child {
            resolve_pending_child(tracee);
        }

        // If the enter stage voided the syscall, an outer seccomp policy may
        // raise SIGSYS on the avoider — swallow that signal next.
        if was_sysenter {
            tracee.skip_next_seccomp_signal =
                get_sysnum(tracee, RegVersion::Current) == Sysnum::Void;
        } else {
            tracee.skip_next_seccomp_signal = false;
        }

        // Redeliver a signal suppressed during a finished chain.
        if tracee.chain.suppressed_signal != 0
            && tracee.chain.syscalls.is_none()
            && !tracee.restore_original_regs_after_seccomp_event
        {
            *signal = tracee.chain.suppressed_signal;
            tracee.chain.suppressed_signal = 0;
            crate::verbose!(
                Some(tracee),
                6,
                "vpid {}: redelivering suppressed signal {}",
                tracee.vpid,
                *signal
            );
        }
    } else {
        crate::verbose!(
            Some(tracee),
            6,
            "skipping SIGTRAP for already handled sysenter"
        );
        debug_assert!(!is_in_sysenter(tracee));
        debug_assert!(!unsafe { SECCOMP_AFTER_PTRACE_ENTER });
        tracee.seccomp_already_handled_enter = false;
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
    }
}

/// PTRACE_EVENT_SECCOMP stop.
fn handle_seccomp_stop(tracee: &mut Tracee, sysexit_necessary: bool) -> i32 {
    let mut signal = 0;

    unsafe {
        if !SECCOMP_DETECTED {
            tracee.seccomp = Seccomp::Enabled;
            SECCOMP_DETECTED = true;
            SECCOMP_AFTER_PTRACE_ENTER = !is_in_sysenter(tracee);
            crate::verbose!(
                Some(tracee),
                1,
                "ptrace acceleration (seccomp mode 2, {} syscall order) enabled",
                if SECCOMP_AFTER_PTRACE_ENTER {
                    "new"
                } else {
                    "old"
                }
            );
        }
    }

    tracee.skip_next_seccomp_signal = false;

    // If the kernel triggers the event after we handled sysenter, skip it.
    if unsafe { SECCOMP_AFTER_PTRACE_ENTER } && !is_in_sysenter(tracee) {
        tracee.restart_how = tracee.last_restart_how;
        crate::verbose!(
            Some(tracee),
            6,
            "skipping PTRACE_EVENT_SECCOMP for already handled sysenter"
        );
        debug_assert_ne!(tracee.restart_how, crate::ptrace::ptc::PTRACE_CONT as i32);
        return signal;
    }

    debug_assert!(is_in_sysenter(tracee));

    // Use the common ptrace flow if seccomp was disabled for this tracee.
    if tracee.seccomp != Seccomp::Enabled {
        return signal;
    }

    let mut flags: Word = 0;
    let status = unsafe {
        libc::ptrace(
            crate::ptrace::ptc::PTRACE_GETEVENTMSG as u32,
            tracee.pid,
            std::ptr::null::<u8>(),
            &mut flags as *mut Word as usize,
        )
    };
    if status < 0 {
        return signal;
    }

    // Kernels that lose event messages: reconstruct flags from the filter.
    unsafe {
        if EVENTMSG_STATE != EventmsgState::Reliable && fetch_regs(tracee) >= 0 {
            let expected = crate::syscall::seccomp::filtered_sysnum_flags(
                tracee,
                get_sysnum(tracee, RegVersion::Current),
            );
            if EVENTMSG_STATE == EventmsgState::Unknown
                && (expected & crate::syscall::seccomp::FILTER_SYSEXIT) != 0
            {
                if (flags & crate::syscall::seccomp::FILTER_SYSEXIT) != 0 {
                    EVENTMSG_STATE = EventmsgState::Reliable;
                } else {
                    EVENTMSG_STATE = EventmsgState::Lost;
                    crate::verbose!(
                        Some(tracee),
                        1,
                        "this kernel loses ptrace event messages (PTRACE_GETEVENTMSG reads 0), working around it"
                    );
                }
            }
            if EVENTMSG_STATE != EventmsgState::Reliable {
                flags |= expected;
            }
        }
    }

    if (flags & crate::syscall::seccomp::FILTER_SYSEXIT) != 0 || sysexit_necessary {
        if unsafe { SECCOMP_AFTER_PTRACE_ENTER } {
            tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
            crate::syscall::translate_syscall(tracee);
        }
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
        return signal;
    }

    // Handle the sysenter stage right now.
    tracee.restart_how = crate::ptrace::ptc::PTRACE_CONT as i32;
    crate::syscall::translate_syscall(tracee);

    if tracee.sysexit_pending {
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
    }
    if tracee.seccomp == Seccomp::Disabling {
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
    }
    if !unsafe { SECCOMP_AFTER_PTRACE_ENTER }
        && tracee.restart_how == crate::ptrace::ptc::PTRACE_SYSCALL as i32
        && !tracee.voided_syscall_cancelled
    {
        tracee.seccomp_already_handled_enter = true;
    }

    signal = 0;
    let _ = &mut signal;
    signal
}

/// `_sigsys._syscall` inside glibc `siginfo_t` on x86_64: the sifields union
/// starts at offset 16 (after signo/errno/code/__pad0), `_call_addr` occupies
/// 8 bytes, so `_syscall` sits at offset 24.
fn sigsys_syscall_nr(siginfo: &libc::siginfo_t) -> i32 {
    const _: () = assert!(std::mem::size_of::<libc::siginfo_t>() == 128);
    unsafe {
        (siginfo as *const _ as *const u8)
            .add(24)
            .cast::<i32>()
            .read()
    }
}

/// SIGSYS delivery (seccomp trap on a syscall we or the tracee filtered).
fn handle_sigsys(tracee: &mut Tracee, mut signal: i32) -> i32 {
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::ptrace(
            crate::ptrace::ptc::PTRACE_GETSIGINFO as u32,
            tracee.pid,
            std::ptr::null::<u8>(),
            &mut siginfo as *mut _ as usize,
        );
    }
    // si_code 1 == SYS_SECCOMP: raised by a seccomp filter.
    const SI_SYS_SECCOMP: i32 = 1;
    if siginfo.si_code == SI_SYS_SECCOMP {
        // The filter that raises SIGSYS also cancels the syscall: no more
        // sysenter stop is coming for it.
        tracee.seccomp_already_handled_enter = false;

        if !is_in_sysenter(tracee) {
            crate::verbose!(Some(tracee), 1, "Handling syscall exit from SIGSYS");
            crate::syscall::translate_syscall(tracee);
            tracee.restore_sysarg1_after_sigsys = true;
        }

        if tracee.skip_next_seccomp_signal
            || sigsys_syscall_nr(&siginfo) == crate::arch::SYSCALL_AVOIDER as i32
        {
            crate::verbose!(Some(tracee), 4, "suppressed SIGSYS after void syscall");
            tracee.skip_next_seccomp_signal = false;
            tracee.restore_sysarg1_after_sigsys = false;
            signal = 0;
        } else {
            signal = crate::tracee::seccomp::handle_seccomp_event(tracee);
        }
    } else {
        crate::verbose!(Some(tracee), 1, "non-seccomp SIGSYS");
    }
    signal
}

/// `check_architecture()` — warn when the exe is a 64-bit program while the
/// build handles 32-bit only (no-op on 64-bit hosts).
fn check_architecture(tracee: &mut Tracee) {
    if tracee.exe.is_none() {
        return;
    }
    let mut path = crate::fpath::FixedPath::new();
    let exe = tracee.exe.clone().unwrap();
    if crate::path::translate_path(tracee, &mut path, libc::AT_FDCWD, exe.as_bytes(), false)
        .is_err()
    {
        return;
    }
    if let Ok((fd, ehdr)) = crate::execve::elf::open_elf(path.as_bytes()) {
        unsafe { libc::close(fd) };
        if !ehdr.is_class64() || std::mem::size_of::<Word>() == 8 {
            return;
        }
        crate::note!(
            crate::note::Severity::Error,
            crate::note::Origin::User,
            "'{}' is a 64-bit program whereas this version of {} handles 32-bit programs only",
            path,
            crate::note::tool_name()
        );
    }
}

/// `restart_tracee()` — resume a stopped tracee.
pub fn restart_tracee(tracee_rc: &TraceeRef, signal: i32) -> bool {
    let mut t = tracee_rc.borrow_mut();
    if t.as_ptracer.wait_pid != 0 || signal == -1 {
        return false;
    }
    debug_assert_ne!(t.restart_how, 0);
    let status = unsafe {
        libc::ptrace(
            t.restart_how as u32,
            t.pid,
            std::ptr::null::<u8>(),
            signal as usize,
        )
    };
    if status < 0 {
        return false; // The process likely died in a syscall.
    }
    t.last_restart_how = t.restart_how;
    t.restart_how = 0;
    t.running = true;
    true
}

/* ================================================================== */
/* Fork/clone child registration (tracee.c)                            */
/* ================================================================== */

/// Read Tgid/PPid/TracerPid from /proc/@pid/status.
fn read_proc_status_ids(pid: i32) -> Option<(i32, i32, i32)> {
    let text = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let (mut tgid, mut ppid, mut tracer) = (None, None, None);
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Tgid:") {
            tgid = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("TracerPid:") {
            tracer = v.trim().parse().ok();
        }
    }
    Some((tgid?, ppid?, tracer?))
}

/// `new_child_stack()` — initial SP of the child the parent just created.
fn new_child_stack(parent: &mut Tracee) -> Word {
    let stack = match get_sysnum(parent, RegVersion::Current) {
        Sysnum::clone => peek_reg(parent, RegVersion::Current, Reg::Sysarg2),
        Sysnum::clone3 => {
            let args = peek_reg(parent, RegVersion::Current, Reg::Sysarg1);
            unsafe { *libc::__errno_location() = 0 };
            let stack = crate::tracee::mem::peek_word(parent, args + 5 * 8);
            let size = crate::tracee::mem::peek_word(parent, args + 6 * 8);
            if crate::path::errno() != 0 || stack == 0 {
                0
            } else {
                stack + size
            }
        }
        _ => 0,
    };
    if stack != 0 {
        stack
    } else {
        peek_reg(parent, RegVersion::Current, Reg::StackPointer)
    }
}

/// `is_pending_child_of()` — match a nameless-stopped tracee to the parent
/// blocked in vfork.
fn is_pending_child_of(parent: &Tracee, child_rc: &TraceeRef) -> bool {
    let flags = parent.pending_clone_flags;
    let child_pid = child_rc.borrow().pid;
    let (child_tgid, child_ppid, _tr) = match read_proc_status_ids(child_pid) {
        Some(v) => v,
        None => return false,
    };
    let (parent_tgid, parent_ppid, _tr) = match read_proc_status_ids(parent.pid) {
        Some(v) => v,
        None => return false,
    };

    let related = if (flags & libc::CLONE_THREAD as Word) != 0 {
        child_tgid == parent_tgid
    } else if (flags & libc::CLONE_PARENT as Word) != 0 {
        child_ppid == parent_ppid
    } else {
        child_ppid == parent_tgid
    };
    if !related {
        return false;
    }

    // The child's untouched stack identifies the matching clone call.
    {
        let mut child = child_rc.borrow_mut();
        if fetch_regs(&mut child) < 0 {
            return false;
        }
        peek_reg(&child, RegVersion::Current, Reg::StackPointer) == parent.pending_child_sp
    }
}

/// `adopt_held_children()` — attach children of parents blocked in vfork.
pub fn adopt_held_children() {
    let pids: Vec<i32> = crate::tracee::all_pids();

    let vfork_pending = pids.iter().any(|&p| {
        get_tracee(p, false)
            .map(|t| {
                let t = t.borrow();
                t.pending_child && (t.pending_clone_flags & libc::CLONE_VFORK as Word) != 0
            })
            .unwrap_or(false)
    });
    if !vfork_pending {
        return;
    }

    for &child_pid in &pids {
        let child_rc = match get_tracee(child_pid, false) {
            Some(c) => c,
            None => continue,
        };
        {
            let c = child_rc.borrow();
            if c.exe.is_some() || c.sigstop != Sigstop::Pending || c.terminated {
                continue;
            }
        }
        for &parent_pid in &pids {
            let parent_rc = match get_tracee(parent_pid, false) {
                Some(p) => p,
                None => continue,
            };
            let ok = {
                let p = parent_rc.borrow();
                p.pending_child
                    && (p.pending_clone_flags & libc::CLONE_VFORK as Word) != 0
                    && p.exe.is_some()
                    && !p.terminated
                    && is_pending_child_of(&p, &child_rc)
            };
            if ok {
                let clone_flags = {
                    let mut p = parent_rc.borrow_mut();
                    p.pending_child = false;
                    p.pending_clone_flags
                };
                let _ = attach_child(&parent_rc, clone_flags, child_pid);
                break;
            }
        }
    }
}

/// `resolve_pending_child()` — the syscall result names the child.
pub fn resolve_pending_child(parent: &mut Tracee) {
    match get_sysnum(parent, RegVersion::Original) {
        Sysnum::clone | Sysnum::clone3 | Sysnum::fork | Sysnum::vfork => {}
        _ => return,
    }

    parent.pending_child = false;
    let pid = peek_reg(parent, RegVersion::Current, Reg::SysargResult) as i32;

    // Already registered by adopt_held_children()?
    let already = if pid > 0 {
        get_tracee(pid, false)
            .map(|c| c.borrow().exe.is_some())
            .unwrap_or(false)
    } else {
        false
    };
    if already {
        return;
    }

    // The pid must name a process we actually trace.
    let ok = pid > 0
        && read_proc_status_ids(pid)
            .map(|(_t, _p, tracer)| tracer == unsafe { libc::getpid() })
            .unwrap_or(false);
    if !ok {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::Internal,
            "vpid {}: can't find the child of a fork reported without its pid",
            parent.vpid
        );
        parent.clone_stripped_newns = false;
        parent.clone_stripped_newnet = false;
        return;
    }
    let flags = parent.pending_clone_flags;
    defer_attach(parent.pid, flags, pid);
}

/// `new_child()` — a fork-like event was reported for `parent_rc`.
pub fn new_child(parent_rc: &TraceeRef, clone_flags: Word) {
    let mut clone_flags = clone_flags;

    {
        let mut parent = parent_rc.borrow_mut();
        let status = fetch_regs(&mut parent);
        if status >= 0 {
            match get_sysnum(&parent, RegVersion::Current) {
                Sysnum::clone => clone_flags = peek_reg(&parent, RegVersion::Current, Reg::Sysarg1),
                Sysnum::clone3 => {
                    // clone_args.flags is the first word of the struct.
                    clone_flags = crate::tracee::mem::peek_word(
                        &parent,
                        peek_reg(&parent, RegVersion::Current, Reg::Sysarg1),
                    )
                }
                _ => {}
            }
        }
    }

    let pid: libc::c_ulong = unsafe {
        let mut msg: libc::c_ulong = 0;
        let status = libc::ptrace(
            crate::ptrace::ptc::PTRACE_GETEVENTMSG as u32,
            parent_rc.borrow().pid,
            std::ptr::null::<u8>(),
            &mut msg as *mut _ as usize,
        );
        if status < 0 || msg == 0 {
            0
        } else {
            msg
        }
    };

    if pid == 0 {
        let mut p = parent_rc.borrow_mut();
        crate::verbose!(
            Some(&p),
            1,
            "vpid {}: fork event without the child's pid",
            p.vpid
        );
        p.pending_child = true;
        p.pending_clone_flags = clone_flags;
        p.pending_child_sp = new_child_stack(&mut p);
        drop(p);
        adopt_held_children();
        return;
    }

    let _ = attach_child(parent_rc, clone_flags, pid as i32);
}

/// `attach_child()` — make the new child inherit from its parent.
pub fn attach_child(parent_rc: &TraceeRef, clone_flags: Word, pid: i32) -> i32 {
    let child_rc = match get_tracee(pid, true) {
        Some(c) => c,
        None => {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "running out of memory"
            );
            return -libc::ENOMEM;
        }
    };

    let mut parent = parent_rc.borrow_mut();
    let mut child = child_rc.borrow_mut();

    child.verbose = parent.verbose;
    child.seccomp = parent.seccomp;
    child.sysexit_pending = parent.sysexit_pending;
    child.execfn_addr = parent.execfn_addr;
    child.auxv_fd = parent.auxv_fd;
    child.no_new_privs = parent.no_new_privs;
    child.seen_execve = parent.seen_execve;

    // CLONE_VM → shared heap; otherwise a private copy.
    child.heap = if (clone_flags & libc::CLONE_VM as Word) != 0 {
        parent.heap.clone()
    } else {
        let copy = parent.heap.borrow().clone_heap();
        Rc::new(RefCell::new(copy))
    };

    child.load_info = parent.load_info.clone();

    child.parent = if (clone_flags & libc::CLONE_PARENT as Word) != 0 {
        parent.parent
    } else {
        parent.pid
    };
    child.is_clone = (clone_flags & libc::CLONE_THREAD as Word) != 0;

    // Auto-attach to the parent's ptracer when its options ask for it.
    let ptrace_options: Word = if clone_flags == 0 {
        crate::ptrace::ptc::PTRACE_O_TRACEFORK as Word
    } else if (clone_flags & 0xFF) == libc::SIGCHLD as Word {
        crate::ptrace::ptc::PTRACE_O_TRACEFORK as Word
    } else if (clone_flags & libc::CLONE_VFORK as Word) != 0 {
        crate::ptrace::ptc::PTRACE_O_TRACEVFORK as Word
    } else {
        crate::ptrace::ptc::PTRACE_O_TRACECLONE as Word
    };
    if parent.as_ptracee.ptracer != 0
        && ((ptrace_options & parent.as_ptracee.options) != 0
            || (clone_flags & libc::CLONE_PTRACE as Word) != 0)
    {
        let ptracer_pid = parent.as_ptracee.ptracer;
        drop(parent);
        crate::ptrace::attach_to_ptracer(&mut child, ptracer_pid);
        parent = parent_rc.borrow_mut();
        child.as_ptracee.options |= parent.as_ptracee.options
            & (crate::ptrace::ptc::PTRACE_O_TRACECLONE
                | crate::ptrace::ptc::PTRACE_O_TRACEEXEC
                | crate::ptrace::ptc::PTRACE_O_TRACEEXIT
                | crate::ptrace::ptc::PTRACE_O_TRACEFORK
                | crate::ptrace::ptc::PTRACE_O_TRACESYSGOOD
                | crate::ptrace::ptc::PTRACE_O_TRACEVFORK
                | crate::ptrace::ptc::PTRACE_O_TRACEVFORKDONE) as Word;
    }

    // CLONE_FS → shared file-system namespace; else a private copy.
    if (clone_flags & libc::CLONE_FS as Word) != 0 {
        child.fs = parent.fs.clone();
    } else {
        let mut new_fs = crate::tracee::FileSystemNameSpace::default();
        new_fs.cwd = parent.fs.borrow().cwd.clone();
        if parent.clone_stripped_newns && !parent.fs.borrow().guest.is_empty() {
            // CLONE_NEWNS was stripped: give the child a private copy of the
            // binding tree so emulated mounts don't propagate back.
            let parent_guest: Vec<Rc<crate::path::binding::Binding>> =
                parent.fs.borrow().guest.clone();
            drop(parent);
            for b in parent_guest {
                let mut nb = crate::path::binding::Binding {
                    host: b.host.clone(),
                    guest: b.guest.clone(),
                    need_substitution: b.need_substitution,
                };
                let _ = &mut nb;
                let rc = Rc::new(nb);
                new_fs.guest.push(rc.clone());
                new_fs.host.push(rc);
            }
            child.fs = Rc::new(RefCell::new(new_fs));
            parent = parent_rc.borrow_mut();
        } else {
            // Bindings are shared across namespaces (mounts propagate).
            new_fs.guest = parent.fs.borrow().guest.clone();
            new_fs.host = parent.fs.borrow().host.clone();
            child.fs = Rc::new(RefCell::new(new_fs));
        }
    }
    parent.clone_stripped_newns = false;

    child.fake_netns = parent.fake_netns || parent.clone_stripped_newnet;
    parent.clone_stripped_newnet = false;

    // Open netlink fds survive fork; pending replies don't.
    child.fake_netlink_fds = parent
        .fake_netlink_fds
        .iter()
        .map(|f| crate::tracee::FakeNetlinkSocket {
            fd: f.fd,
            reply: Vec::new(),
            reply_off: 0,
        })
        .collect();
    child.netlink_route_fds = parent.netlink_route_fds.clone();

    child.exe = parent.exe.clone();
    child.qemu = parent.qemu.clone();
    child.glue = parent.glue.clone();
    child.host_ldso_paths = parent.host_ldso_paths.clone();
    child.guest_ldso_paths = parent.guest_ldso_paths.clone();

    crate::extension::inherit_extensions(&mut child, &mut parent, clone_flags);

    // Restart a child that was stopped waiting for its event.
    if child.sigstop == Sigstop::Pending {
        let mut keep_stopped = false;
        child.sigstop = Sigstop::Allowed;

        if child.as_ptracee.ptracer != 0 {
            debug_assert!(!child.as_ptracee.tracing_started);
            drop(parent);
            let child_pid = child.pid;
            drop(child);
            keep_stopped =
                crate::ptrace::wait::handle_ptracee_event(&child_rc, (libc::SIGSTOP << 8) | 0x7f);
            child = child_rc.borrow_mut();
            let _ = child_pid;
            child.as_ptracee.event4.proot.pending = false;
            child.as_ptracee.event4.proot.value = 0;
            parent = parent_rc.borrow_mut();
        }

        if !keep_stopped {
            drop(child);
            drop(parent);
            restart_tracee(&child_rc, 0);
            return 0;
        }
    }

    crate::verbose!(Some(&child), 1, "vpid {}: pid {}", child.vpid, child.pid);

    0
}
