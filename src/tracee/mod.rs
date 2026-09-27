//! Tracee process model — port of tracee/tracee.h + tracee.c.

pub mod abi;
pub mod event;
pub mod mem;
pub mod reg;
pub mod statx;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::extension::AnyExtension;
use crate::syscall::chain::Chain;
use crate::syscall::heap::Heap;
use crate::sysnum::Sysnum;
use crate::Word;

pub use reg::{Reg, RegVersion, Regs};

/// File-system name-space shared between tracees that cloned with CLONE_FS.
#[derive(Default)]
pub struct FileSystemNameSpace {
    pub pending: Vec<Rc<crate::path::binding::Binding>>,
    pub guest: Vec<Rc<crate::path::binding::Binding>>,
    pub host: Vec<Rc<crate::path::binding::Binding>>,
    /// Canonicalized *guest* cwd (`/proc/self/pwd` equivalent).
    pub cwd: crate::fpath::FixedPath,
}



/// ptrace emulation: this tracee acting as a tracer.
#[derive(Default)]
pub struct AsPtracer {
    pub nb_ptracees: usize,
    pub zombies: Vec<crate::tracee::TraceeId>,
    pub wait_pid: i32,
    pub wait_options: Word,
    pub waits_in: WaitsIn,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum WaitsIn {
    #[default]
    DoesntWait = 0,
    Kernel,
    Proot,
}

/// ptrace emulation: this tracee being traced by another tracee.
#[derive(Default)]
pub struct AsPtracee {
    /// pid of the ptracing tracee (0 = none).
    pub ptracer: i32,
    pub event4: Event4,
    pub tracing_started: bool,
    pub ignore_loader_syscalls: bool,
    pub ignore_syscalls: bool,
    pub options: Word,
    pub is_zombie: bool,
}

#[derive(Default)]
pub struct Event4 {
    pub proot: PEvent,
    pub ptracer: PEvent,
}

#[derive(Default)]
pub struct PEvent {
    pub value: i32,
    pub pending: bool,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Seccomp {
    #[default]
    Disabled = 0,
    Disabling,
    Enabled,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Sigstop {
    #[default]
    Ignored = 0,
    Allowed,
    Pending,
}

/// pid → internal index.  Tracees are stored in a global arena so that
/// cross-references stay cheap keys rather than borrowed pointers.
pub type TraceeId = usize;

#[derive(Default)]
pub struct FakeNetlinkSocket {
    pub fd: i32,
    pub reply: Vec<u8>,
    pub reply_off: usize,
}

pub const MAX_FAKE_NETLINK_FDS: usize = 8;
pub const MAX_FAKE_NETLINK_REPLY: usize = 8192;
pub const MAX_NETLINK_ROUTE_FDS: usize = 8;

pub struct Tracee {
    pub pid: i32,
    pub vpid: u64,
    pub running: bool,
    pub terminated: bool,
    pub killall_on_exit: bool,

    /// pid of the tracee that created this one (0 = none).
    pub parent: i32,
    pub is_clone: bool,
    pub clone_stripped_newns: bool,
    pub clone_stripped_newnet: bool,
    pub fake_netns: bool,

    pub fake_netlink_fds: Vec<FakeNetlinkSocket>,
    pub pending_fake_netlink_socket: bool,
    pub netlink_route_fds: Vec<i32>,
    pub pending_real_netlink_socket: bool,
    pub netlink_ack_pending: bool,
    pub netlink_ack_fd: i32,
    pub netlink_ack_seq: u32,

    pub as_ptracer: AsPtracer,
    pub as_ptracee: AsPtracee,

    /// 0: sysenter, 1: sysexit-ok, -errno: sysexit-error.
    pub status: i32,

    pub restart_how: i32,
    pub last_restart_how: i32,

    /// Register banks: [CURRENT, ORIGINAL, MODIFIED, ORIGINAL_SECCOMP_REWRITE].
    pub regs: [Regs; 4],
    pub regs_were_changed: bool,
    pub restore_original_regs: bool,
    pub restore_original_regs_after_seccomp_event: bool,

    pub sigstop: Sigstop,
    pub skip_next_seccomp_signal: bool,
    pub voided_syscall_cancelled: bool,
    pub restore_sysarg1_after_sigsys: bool,

    /// Type of the final component while initializing a binding (glue).
    pub glue_type: u32,

    /// Sub-reconfiguration context: tracee + $PATH.
    pub reconf_tracee: Option<TraceeId>,
    pub reconf_paths: Option<String>,

    /// Chained syscalls inserted after an actual syscall.
    pub chain: Chain,

    /// Load info generated during execve sysenter (used at sysexit).
    pub load_info: Option<Box<crate::execve::LoadInfo>>,

    /// Address of argv[0] on the initial stack (AT_EXECFN fixup).
    pub execfn_addr: Word,

    /// fd the tracee used to open /proc/self/auxv (-1 = inactive).
    pub auxv_fd: i32,

    /* ---- inherited private resources ---- */
    pub verbose: i32,
    pub seccomp: Seccomp,
    pub sysexit_pending: bool,
    pub pending_child: bool,
    pub pending_clone_flags: Word,
    pub pending_child_sp: Word,
    pub seccomp_already_handled_enter: bool,
    pub no_new_privs: bool,
    pub seen_execve: bool,

    /* ---- CLONE_FS/VM-shared resources ---- */
    pub fs: Rc<RefCell<FileSystemNameSpace>>,
    pub heap: Rc<RefCell<Heap>>,

    /* ---- shared until execve ---- */
    /// Path to the executable, a'la /proc/self/exe (guest canonical).
    pub exe: Option<Rc<String>>,
    pub new_exe: Option<String>,
    pub host_exe: Option<String>,

    /* ---- configuration ---- */
    pub qemu: Option<Rc<Vec<String>>>,
    pub skip_proot_loader: bool,
    pub glue: Option<Rc<String>>,
    pub extensions: Vec<Option<AnyExtension>>,

    /* ---- read-only shared ---- */
    pub host_ldso_paths: Option<Rc<String>>,
    pub guest_ldso_paths: Option<Rc<String>>,

    /// Scratch storage for the "still in sysenter" execve bookkeeping.
    pub execve_pending: Option<ExecvePending>,
}

/// Bookkeeping saved between execve sysenter and sysexit.
pub struct ExecvePending {
    pub load_info: Box<crate::execve::LoadInfo>,
}

impl Default for Tracee {
    fn default() -> Self {
        Tracee {
            pid: 0,
            vpid: 0,
            running: false,
            terminated: false,
            killall_on_exit: false,
            parent: 0,
            is_clone: false,
            clone_stripped_newns: false,
            clone_stripped_newnet: false,
            fake_netns: false,
            fake_netlink_fds: Vec::new(),
            pending_fake_netlink_socket: false,
            netlink_route_fds: Vec::new(),
            pending_real_netlink_socket: false,
            netlink_ack_pending: false,
            netlink_ack_fd: -1,
            netlink_ack_seq: 0,
            as_ptracer: AsPtracer::default(),
            as_ptracee: AsPtracee::default(),
            status: 0,
            restart_how: 0,
            last_restart_how: 0,
            regs: unsafe { std::mem::zeroed() },
            regs_were_changed: false,
            restore_original_regs: true,
            restore_original_regs_after_seccomp_event: false,
            sigstop: Sigstop::Ignored,
            skip_next_seccomp_signal: false,
            voided_syscall_cancelled: false,
            restore_sysarg1_after_sigsys: false,
            glue_type: 0,
            reconf_tracee: None,
            reconf_paths: None,
            chain: Chain::default(),
            load_info: None,
            execfn_addr: 0,
            auxv_fd: -1,
            verbose: 0,
            seccomp: Seccomp::Disabled,
            sysexit_pending: false,
            pending_child: false,
            pending_clone_flags: 0,
            pending_child_sp: 0,
            seccomp_already_handled_enter: false,
            no_new_privs: false,
            seen_execve: false,
            fs: Rc::new(RefCell::new(FileSystemNameSpace {
                cwd: crate::fpath::FixedPath::from_bytes(b"/"),
                ..FileSystemNameSpace::default()
            })),
            heap: Rc::new(RefCell::new(Heap::default())),
            exe: None,
            new_exe: None,
            host_exe: None,
            qemu: None,
            skip_proot_loader: false,
            glue: None,
            extensions: Vec::new(),
            host_ldso_paths: None,
            guest_ldso_paths: None,
            execve_pending: None,
        }
    }
}

/* ================================================================== */
/* Global tracee registry                                              */
/* ================================================================== */

thread_local! {
    static TRACEES: RefCell<HashMap<i32, Rc<RefCell<Tracee>>>> = RefCell::new(HashMap::new());
    static TRACEE_ORDER: RefCell<Vec<i32>> = RefCell::new(Vec::new());
    static NEXT_VPID: RefCell<u64> = RefCell::new(1);
    /// Pid of the first tracee (for "-k" / last exit status reporting).
    pub static FIRST_TRACEE_PID: RefCell<i32> = RefCell::new(0);
}

/// Borrow the tracee map immutably for `f`.
pub fn with_tracee<R>(pid: i32, f: impl FnOnce(&Tracee) -> R) -> Option<R> {
    TRACEES.with(|t| t.borrow().get(&pid).map(|rc| f(&rc.borrow())))
}

/// Borrow the tracee map mutably for `f`.
pub fn with_tracee_mut<R>(pid: i32, f: impl FnOnce(&mut Tracee) -> R) -> Option<R> {
    TRACEES.with(|t| t.borrow().get(&pid).map(|rc| f(&mut rc.borrow_mut())))
}

/// Get an `Rc` handle on the tracee with @pid, creating+registering a fresh
/// one when `create` is true.
pub fn get_tracee(pid: i32, create: bool) -> Option<Rc<RefCell<Tracee>>> {
    TRACEES.with(|map| {
        if let Some(rc) = map.borrow().get(&pid) {
            return Some(rc.clone());
        }
        if !create {
            return None;
        }
        let vpid = NEXT_VPID.with(|v| {
            let v = &mut *v.borrow_mut();
            let cur = *v;
            *v += 1;
            cur
        });
        let t = Tracee { pid, vpid, ..Tracee::default() };
        let rc = Rc::new(RefCell::new(t));
        map.borrow_mut().insert(pid, rc.clone());
        TRACEE_ORDER.with(|o| o.borrow_mut().push(pid));
        Some(rc)
    })
}

/// Iterating helper: runs `f` on each live tracee (snapshot of pids).
pub fn for_each_tracee(mut f: impl FnMut(Rc<RefCell<Tracee>>)) {
    let pids: Vec<i32> = TRACEE_ORDER.with(|o| o.borrow().clone());
    for pid in pids {
        if let Some(rc) = get_tracee(pid, false) {
            f(rc);
        }
    }
}

pub fn tracee_count() -> usize {
    TRACEES.with(|t| t.borrow().len())
}

pub fn verbose_of(tracee: Option<&Tracee>) -> i32 {
    match tracee {
        Some(t) => t.verbose,
        None => crate::note::global_verbose(),
    }
}

/// Shortcut for `tracee.status == 0` (IS_IN_SYSENTER).
#[inline]
pub fn is_in_sysenter(tracee: &Tracee) -> bool {
    tracee.status == 0
}

#[inline]
pub fn is_in_sysexit(tracee: &Tracee) -> bool {
    !is_in_sysenter(tracee)
}

#[inline]
pub fn is_in_sysexit2(tracee: &Tracee, sysnum: Sysnum) -> bool {
    is_in_sysexit(tracee) && crate::tracee::reg::get_sysnum(tracee, RegVersion::Original) == sysnum
}

/* ================================================================== */
/* Lifecycle                                                           */
/* ================================================================== */

/// `terminate_tracee()` — mark a tracee dead; actual removal happens in
/// `free_terminated_tracees()` at a safe point in the event loop.
pub fn terminate_tracee(pid: i32) {
    with_tracee_mut(pid, |t| {
        t.terminated = true;
        t.running = false;
    });
}

/// Reap terminated tracees: drop their registry entries and unlink auxv
/// bindings etc.  The single-threaded event loop is the only caller.
pub fn free_terminated_tracees() {
    let dead: Vec<i32> = TRACEES.with(|map| {
        map.borrow()
            .values()
            .filter(|rc| rc.borrow().terminated)
            .map(|rc| rc.borrow().pid)
            .collect()
    });
    for pid in dead {
        // Give extensions a chance to release per-tracee state.
        if let Some(rc) = get_tracee(pid, false) {
            let mut t = rc.borrow_mut();
            let exts = std::mem::take(&mut t.extensions);
            drop(t);
            drop(exts);
        }
        TRACEES.with(|m| m.borrow_mut().remove(&pid));
        TRACEE_ORDER.with(|o| o.borrow_mut().retain(|&p| p != pid));
    }
}

/// `kill_all_tracees()` — SIGKILL everything still registered.
pub fn kill_all_tracees() {
    for_each_tracee(|rc| {
        let pid = rc.borrow().pid;
        unsafe { libc::kill(pid, libc::SIGKILL) };
    });
}
