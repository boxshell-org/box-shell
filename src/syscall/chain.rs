//! Chained syscalls — port of syscall/chain.c.

use std::collections::VecDeque;

use crate::sysnum::Sysnum;
use crate::tracee::reg::{get_sysnum, peek_reg, poke_reg, Reg, RegVersion};
use crate::tracee::Tracee;
use crate::Word;

#[derive(Copy, Clone)]
pub struct ChainedSyscall {
    pub sysnum: Sysnum,
    pub sysargs: [Word; 6],
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SysnumWorkaround {
    #[default]
    Inactive,
    ProcessFaultyCall,
    ProcessReplacedCall,
}

#[derive(Default)]
pub struct Chain {
    pub syscalls: VecDeque<ChainedSyscall>,
    pub force_final_result: bool,
    pub final_result: Word,
    pub sysnum_workaround_state: SysnumWorkaround,
    pub suppressed_signal: i32,
}

/// `register_chained_syscall()` — queue an unrequested syscall to run after
/// the current one completes.
pub fn register_chained_syscall(tracee: &mut Tracee, sysnum: Sysnum, sysargs: [Word; 6]) -> i32 {
    tracee.chain.syscalls.push_back(ChainedSyscall { sysnum, sysargs });
    0
}

fn register_at_front(tracee: &mut Tracee, sysnum: Sysnum, sysargs: [Word; 6]) -> i32 {
    tracee.chain.syscalls.push_front(ChainedSyscall { sysnum, sysargs });
    0
}

/// `chain_next_syscall()` — pop the next chained syscall and arm it: move the
/// instruction pointer back onto the trap and rewrite sysargs.
pub fn chain_next_syscall(tracee: &mut Tracee) {
    match tracee.chain.syscalls.pop_front() {
        None => {
            if tracee.chain.force_final_result {
                let r = tracee.chain.final_result;
                poke_reg(tracee, Reg::SysargResult, r);
            }
            tracee.chain.force_final_result = false;
            tracee.chain.final_result = 0;
            crate::verbose!(Some(tracee), 2, "chain_next_syscall finish");
        }
        Some(syscall) => {
            crate::verbose!(Some(tracee), 2, "chain_next_syscall continue");
            // Original registers are restored after the last chained syscall.
            tracee.restore_original_regs = false;
            for (i, arg) in syscall.sysargs.iter().enumerate() {
                poke_reg(tracee, crate::tracee::reg::sysarg(i + 1), *arg);
            }
            crate::tracee::reg::set_sysnum(tracee, syscall.sysnum);
            let ip = peek_reg(tracee, RegVersion::Current, Reg::InstrPointer);
            poke_reg(
                tracee,
                Reg::InstrPointer,
                ip.wrapping_sub(crate::tracee::reg::get_systrap_size(tracee)),
            );
            // Break after exit from this syscall; more may be chained.
            tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL as i32;
        }
    }
}

/// `force_chain_final_result()`.
pub fn force_chain_final_result(tracee: &mut Tracee, forced_result: Word) {
    tracee.chain.force_final_result = true;
    tracee.chain.final_result = forced_result;
}

/// `restart_original_syscall()` — re-run the syscall the tracee requested.
pub fn restart_original_syscall(tracee: &mut Tracee) -> i32 {
    let sysargs = [
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg1),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg2),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg3),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg4),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg5),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg6),
    ];
    register_chained_syscall(tracee, get_sysnum(tracee, RegVersion::Original), sysargs)
}

/// `restart_current_syscall_as_chained()`.
pub fn restart_current_syscall_as_chained(tracee: &mut Tracee) -> i32 {
    debug_assert_eq!(
        tracee.chain.sysnum_workaround_state,
        SysnumWorkaround::Inactive
    );
    tracee.chain.sysnum_workaround_state = SysnumWorkaround::ProcessFaultyCall;
    let sysargs = [
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg3),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg4),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg5),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg6),
    ];
    register_at_front(tracee, get_sysnum(tracee, RegVersion::Current), sysargs)
}
