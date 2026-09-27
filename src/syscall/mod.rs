//! Syscall translation — port of src/syscall/* (syscall.c dispatcher,
//! enter/exit stages, chain, heap, seccomp, sockets, rlimit, pipe shadowing).

pub mod chain;
pub mod enter;
pub mod exit;
pub mod heap;
pub mod netlink;
pub mod pipe_shadow;
pub mod rlimit;
pub mod seccomp;
pub mod socket;

use crate::fpath::FixedPath;
use crate::sysnum::Sysnum;
use crate::tracee::mem::{alloc_mem, read_path, write_data};
use crate::tracee::reg::{
    fetch_regs, get_sysnum, peek_reg, poke_reg, push_specific_regs, save_current_regs, set_sysnum,
    Reg, RegVersion,
};
use crate::tracee::{is_in_sysenter, Tracee};
use crate::Word;

/// `readlink_proc_fd_state` — payload of the READLINK_PROC_FD extension
/// event (syscall.h).
pub struct ReadlinkProcFdState {
    pub pid: i32,
    pub fd: i32,
    pub host_path: FixedPath,
    pub referer: FixedPath,
}

/// `get_sysarg_path()` — read the path pointed to by `reg` of the current
/// syscall into `path`.  Returns its length incl. NUL or -errno.
pub fn get_sysarg_path(tracee: &Tracee, path: &mut FixedPath, reg: Reg) -> i32 {
    let src = peek_reg(tracee, RegVersion::Current, reg);
    if src == 0 {
        path.set(b"");
        return 0;
    }
    read_path(tracee, path, src)
}

/// `set_sysarg_data()` — copy `data` into the tracee (stack allocation) and
/// point `reg` at it.
pub fn set_sysarg_data(tracee: &mut Tracee, data: &[u8], reg: Reg) -> i32 {
    let ptr = alloc_mem(tracee, data.len() as i64);
    if ptr == 0 {
        return -libc::EFAULT;
    }
    let status = write_data(tracee, ptr, data);
    if status < 0 {
        return status;
    }
    poke_reg(tracee, reg, ptr);
    0
}

/// `set_sysarg_path()`.
pub fn set_sysarg_path(tracee: &mut Tracee, path: &[u8], reg: Reg) -> i32 {
    let mut buf = Vec::with_capacity(path.len() + 1);
    buf.extend_from_slice(path);
    buf.push(0);
    set_sysarg_data(tracee, &buf, reg)
}

/// `is_voided_syscall()` — whether `version` holds the avoider PRoot
/// substituted for the original syscall.
pub fn is_voided_syscall(tracee: &Tracee, version: RegVersion) -> bool {
    let mut avoider = crate::arch::SYSCALL_AVOIDER;
    if crate::tracee::reg::is_32on64_mode(tracee) {
        avoider &= 0xFFFF_FFFF;
    }
    peek_reg(tracee, version, Reg::SysargNum) == avoider
        && peek_reg(tracee, RegVersion::Original, Reg::SysargNum) != avoider
}

/// Whether the host kernel cancels a voided syscall instead of letting the
/// avoider run — true when the avoider is negative on this architecture.
fn kernel_cancels_voided_syscall() -> bool {
    (crate::arch::SYSCALL_AVOIDER as i64) < 0
}

/// `translate_syscall()` — dispatch one sysenter/sysexit stop.
pub fn translate_syscall(tracee: &mut Tracee) {
    let is_enter_stage = is_in_sysenter(tracee);
    debug_assert!(tracee.exe.is_some());

    if fetch_regs(tracee) < 0 {
        return;
    }

    let mut suppressed_syscall_status = 0;

    if is_enter_stage {
        tracee.restore_original_regs = false;
        tracee.voided_syscall_cancelled = false;

        crate::tracee::reg::print_current_regs(tracee, 3, "sysenter start");

        let mut status = 0;
        // Only translate a syscall the tracee actually requested — chained
        // ones are just announced to extensions.
        if tracee.chain.syscalls.is_empty() {
            save_current_regs(tracee, RegVersion::Original);
            status = enter::translate_syscall_enter(tracee);
            save_current_regs(tracee, RegVersion::Modified);
        } else {
            if tracee.chain.sysnum_workaround_state
                != chain::SysnumWorkaround::ProcessReplacedCall
            {
                let _ = crate::extension::notify(
                    tracee,
                    &mut crate::extension::Event::ChainedEnter,
                );
            }
            tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
        }

        if status < 0 {
            // Translation failed: void the syscall, fake the result.
            set_sysnum(tracee, Sysnum::Void);
            poke_reg(tracee, Reg::SysargResult, status as Word);
            tracee.status = status;
        } else {
            tracee.status = 1;
            // A voided syscall whose avoider reaches the kernel may have its
            // faked result clobbered — force the exit stage to restore it.
            if is_voided_syscall(tracee, RegVersion::Current)
                && !kernel_cancels_voided_syscall()
            {
                tracee.sysexit_pending = true;
                tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
            }
        }

        // If there's no sysexit stage (seccomp+PTRACE_CONT), restore the
        // stack pointer now.
        if tracee.restart_how == crate::ptrace::ptc::PTRACE_CONT as i32 {
            suppressed_syscall_status = tracee.status;
            tracee.status = 0;
            let sp = peek_reg(tracee, RegVersion::Original, Reg::StackPointer);
            poke_reg(tracee, Reg::StackPointer, sp);
        }
    } else {
        tracee.restore_original_regs = true;
        crate::tracee::reg::print_current_regs(tracee, 5, "sysexit start");

        if tracee.chain.syscalls.is_empty()
            || tracee.chain.sysnum_workaround_state
                == chain::SysnumWorkaround::ProcessReplacedCall
        {
            tracee.chain.sysnum_workaround_state = chain::SysnumWorkaround::Inactive;
            exit::translate_syscall_exit(tracee);
        } else if tracee.chain.sysnum_workaround_state
            == chain::SysnumWorkaround::ProcessFaultyCall
        {
            tracee.chain.sysnum_workaround_state =
                chain::SysnumWorkaround::ProcessReplacedCall;
        } else {
            let _ = crate::extension::notify(
                tracee,
                &mut crate::extension::Event::ChainedExit,
            );
        }

        tracee.status = 0;

        if !tracee.chain.syscalls.is_empty() {
            chain::chain_next_syscall(tracee);
        }
    }

    let override_sysnum = is_enter_stage && tracee.chain.syscalls.is_empty();
    let mut push_regs_status = push_specific_regs(tracee, override_sysnum);
    let sysnum_pushed = override_sysnum && push_regs_status == 0;

    // The kernel may refuse to change the syscall number (rare): make the
    // original syscall fail instead.
    if push_regs_status < 0 && override_sysnum {
        let orig_sysnum = peek_reg(tracee, RegVersion::Original, Reg::SysargNum);
        let current_sysnum = peek_reg(tracee, RegVersion::Current, Reg::SysargNum);
        crate::tracee::reg::print_current_regs(tracee, 4, "pre_push");
        if orig_sysnum != current_sysnum {
            if current_sysnum != crate::arch::SYSCALL_AVOIDER {
                chain::restart_current_syscall_as_chained(tracee);
            } else if suppressed_syscall_status != 0 {
                tracee.status = suppressed_syscall_status;
                tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
            }

            // Force the real syscall to fail with invalid arguments.
            poke_reg(tracee, Reg::Sysarg1, Word::MAX);
            poke_reg(tracee, Reg::Sysarg2, Word::MAX);
            poke_reg(tracee, Reg::Sysarg3, Word::MAX);
            poke_reg(tracee, Reg::Sysarg4, Word::MAX);
            poke_reg(tracee, Reg::Sysarg5, Word::MAX);
            poke_reg(tracee, Reg::Sysarg6, Word::MAX);
            if get_sysnum(tracee, RegVersion::Original) == Sysnum::brk {
                poke_reg(tracee, Reg::Sysarg1, 0);
            }

            push_regs_status = push_specific_regs(tracee, false);
            if push_regs_status != 0 {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::System,
                    "can't set tracee registers in workaround"
                );
            }
        }
    }

    if is_enter_stage {
        tracee.voided_syscall_cancelled = sysnum_pushed
            && kernel_cancels_voided_syscall()
            && is_voided_syscall(tracee, RegVersion::Current);
        crate::tracee::reg::print_current_regs(tracee, 5, "sysenter end");
    } else {
        crate::tracee::reg::print_current_regs(tracee, 4, "sysexit end");
    }
}
