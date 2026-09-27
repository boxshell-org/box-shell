//! Register access — port of tracee/reg.c.
//!
//! Each tracee caches four register banks ([`RegVersion`]); `peek_reg` reads
//! the cache, `poke_reg` marks the CURRENT bank dirty for the next
//! `push_regs`.  Register *indices* are ABI-neutral ([`Reg`]); the offset
//! table resolves the ABI currently in use.

use crate::Word;
use crate::sysnum::{Abi, Sysnum, detranslate_sysnum, translate_sysnum};
use crate::tracee::Tracee;

/// Snapshot selector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RegVersion {
    Current = 0,
    Original = 1,
    Modified = 2,
    OriginalSeccompRewrite = 3,
}

impl RegVersion {
    pub const COUNT: usize = 4;
    #[inline]
    pub fn idx(self) -> usize {
        self as usize
    }
}

/// ABI-neutral register indices (same names as the C enum).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Reg {
    SysargNum = 0,
    Sysarg1,
    Sysarg2,
    Sysarg3,
    Sysarg4,
    Sysarg5,
    Sysarg6,
    SysargResult,
    StackPointer,
    InstrPointer,
    RtldFini,
    StateFlags,
    Userarg1,
}

pub const NB_REGS: usize = 13;

/// Cached general-purpose registers — `struct user_regs_struct` on x86_64.
pub type Regs = libc::user_regs_struct;

/// Field offsets into `user_regs_struct` for the x86_64 ABI.
/// (`std::mem::offset_of!` — stable since Rust 1.77.)
macro_rules! reg_offset {
    ($field:ident) => {
        std::mem::offset_of!(libc::user_regs_struct, $field)
    };
}

const REG_OFFSET_X86_64: [usize; NB_REGS] = [
    reg_offset!(orig_rax), // SYSARG_NUM
    reg_offset!(rdi),      // SYSARG_1
    reg_offset!(rsi),      // SYSARG_2
    reg_offset!(rdx),      // SYSARG_3
    reg_offset!(r10),      // SYSARG_4
    reg_offset!(r8),       // SYSARG_5
    reg_offset!(r9),       // SYSARG_6
    reg_offset!(rax),      // SYSARG_RESULT
    reg_offset!(rsp),      // STACK_POINTER
    reg_offset!(rip),      // INSTR_POINTER
    reg_offset!(rdx),      // RTLD_FINI
    reg_offset!(eflags),   // STATE_FLAGS
    reg_offset!(rdi),      // USERARG_1
];

/// Field offsets for the i386 ABI (32-bit syscall convention) as seen in a
/// `user_regs_struct` produced by a 64-bit kernel.
const REG_OFFSET_I386: [usize; NB_REGS] = [
    reg_offset!(orig_rax),
    reg_offset!(rbx),
    reg_offset!(rcx),
    reg_offset!(rdx),
    reg_offset!(rsi),
    reg_offset!(rdi),
    reg_offset!(rbp),
    reg_offset!(rax),
    reg_offset!(rsp),
    reg_offset!(rip),
    reg_offset!(rdx),
    reg_offset!(eflags),
    reg_offset!(rax),
];

/// SYSARG_1..SYSARG_6 by 1-based index (used by the chain machinery).
pub fn sysarg(index: usize) -> Reg {
    debug_assert!((1..=6).contains(&index));
    match index {
        1 => Reg::Sysarg1,
        2 => Reg::Sysarg2,
        3 => Reg::Sysarg3,
        4 => Reg::Sysarg4,
        5 => Reg::Sysarg5,
        6 => Reg::Sysarg6,
        _ => unreachable!(),
    }
}

/// Current ABI of the tracee (`get_abi()`): relies on ORIGINAL regs since an
/// ABI change takes effect only when the syscall fully returns.
pub fn get_abi(tracee: &Tracee) -> Abi {
    let cs = tracee.regs[RegVersion::Original.idx()].cs;
    match cs {
        0x23 => Abi::Abi2,
        0x33 => {
            if tracee.regs[RegVersion::Original.idx()].ds == 0x2B {
                Abi::Abi3
            } else {
                Abi::Default
            }
        }
        _ => Abi::Default,
    }
}

/// Whether the tracee is a 32-bit process (x86 or x32) — CURRENT regs since
/// the mode switch is effective immediately.
pub fn is_32on64_mode(tracee: &Tracee) -> bool {
    let cs = tracee.regs[RegVersion::Current.idx()].cs;
    match cs {
        0x23 => true,
        0x33 => tracee.regs[RegVersion::Current.idx()].ds == 0x2B,
        _ => false,
    }
}

/// Size of a guest word for the ABI currently in use.
pub fn sizeof_word(tracee: &Tracee) -> usize {
    if is_32on64_mode(tracee) { 4 } else { 8 }
}

#[inline]
fn reg_offsets(tracee: &Tracee, version: RegVersion) -> &'static [usize; NB_REGS] {
    // i386 register conventions apply when cs == 0x23 for *that* bank.
    if tracee.regs[version.idx()].cs == 0x23 {
        &REG_OFFSET_I386
    } else {
        &REG_OFFSET_X86_64
    }
}

fn reg_ptr(regs: &Regs, off: usize) -> *const u64 {
    unsafe { (regs as *const Regs as *const u8).add(off) as *const u64 }
}
fn reg_ptr_mut(regs: &mut Regs, off: usize) -> *mut u64 {
    unsafe { (regs as *mut Regs as *mut u8).add(off) as *mut u64 }
}

/// `peek_reg()` — read the cached value of `reg` in `version`.
pub fn peek_reg(tracee: &Tracee, version: RegVersion, reg: Reg) -> Word {
    let off = reg_offsets(tracee, version)[reg as usize];
    let mut v = unsafe { *reg_ptr(&tracee.regs[version.idx()], off) };
    if is_32on64_mode(tracee) {
        v &= 0xFFFF_FFFF;
    }
    v
}

/// `poke_reg()` — update the CURRENT cache; schedules a PTRACE_SETREGS.
pub fn poke_reg(tracee: &mut Tracee, reg: Reg, value: Word) {
    if peek_reg(tracee, RegVersion::Current, reg) == value {
        return;
    }
    let off = reg_offsets(tracee, RegVersion::Current)[reg as usize];
    unsafe { *reg_ptr_mut(&mut tracee.regs[RegVersion::Current.idx()], off) = value };
    tracee.regs_were_changed = true;
}

/// `save_current_regs()` — snapshot CURRENT into `version`.
pub fn save_current_regs(tracee: &mut Tracee, version: RegVersion) {
    if version == RegVersion::Original {
        tracee.regs_were_changed = false;
    }
    tracee.regs[version.idx()] = tracee.regs[RegVersion::Current.idx()];
}

/// `fetch_regs()` — refresh the CURRENT bank from the kernel.
pub fn fetch_regs(tracee: &mut Tracee) -> i32 {
    let status = unsafe {
        libc::ptrace(
            crate::ptrace::ptc::PTRACE_GETREGS as u32,
            tracee.pid,
            std::ptr::null_mut::<libc::c_void>(),
            &mut tracee.regs[RegVersion::Current.idx()] as *mut _ as *mut libc::c_void,
        )
    };
    if status < 0 {
        return status as i32;
    }
    0
}

/// `push_specific_regs()` — write back the CURRENT bank; optionally including
/// the syscall number (needed when PRoot rewrote it at sysenter).
pub fn push_specific_regs(tracee: &mut Tracee, including_sysnum: bool) -> i32 {
    if tracee.regs_were_changed
        || (tracee.restore_original_regs && tracee.restore_original_regs_after_seccomp_event)
    {
        if tracee.restore_original_regs {
            let from = if tracee.restore_original_regs_after_seccomp_event {
                tracee.restore_original_regs_after_seccomp_event = false;
                RegVersion::OriginalSeccompRewrite
            } else {
                RegVersion::Original
            };
            // On x86_64 the sysarg regs never alias the result register; on
            // x32/i386 they don't either (result is rax).  Just restore all.
            for r in [
                Reg::SysargNum,
                Reg::Sysarg1,
                Reg::Sysarg2,
                Reg::Sysarg3,
                Reg::Sysarg4,
                Reg::Sysarg5,
                Reg::Sysarg6,
                Reg::StackPointer,
            ] {
                let src_off = reg_offsets(tracee, from)[r as usize];
                let dst_off = reg_offsets(tracee, RegVersion::Current)[r as usize];
                let v = unsafe { *reg_ptr(&tracee.regs[from.idx()], src_off) };
                unsafe { *reg_ptr_mut(&mut tracee.regs[RegVersion::Current.idx()], dst_off) = v };
            }
        }
        // including_sysnum is a no-op on x86_64: orig_rax is part of the
        // register set pushed by PTRACE_SETREGS anyway.
        let _ = including_sysnum;
        let status = unsafe {
            libc::ptrace(
                crate::ptrace::ptc::PTRACE_SETREGS as u32,
                tracee.pid,
                std::ptr::null_mut::<libc::c_void>(),
                &tracee.regs[RegVersion::Current.idx()] as *const _ as *const libc::c_void,
            )
        };
        if status < 0 {
            return status as i32;
        }
    }
    0
}

pub fn push_regs(tracee: &mut Tracee) -> i32 {
    push_specific_regs(tracee, true)
}

/// Neutral sysnum of the tracee's syscall in `version`.
pub fn get_sysnum(tracee: &Tracee, version: RegVersion) -> Sysnum {
    translate_sysnum(get_abi(tracee), peek_reg(tracee, version, Reg::SysargNum))
}

/// Overwrite the tracee's current syscall number (auto-detranslated).
pub fn set_sysnum(tracee: &mut Tracee, sysnum: Sysnum) {
    let n = detranslate_sysnum(get_abi(tracee), sysnum);
    poke_reg(tracee, Reg::SysargNum, n);
}

/// Human-readable name of a Sysnum.
pub fn stringify_sysnum(s: Sysnum) -> &'static str {
    s.name()
}

/// Verbose register dump.
pub fn print_current_regs(tracee: &Tracee, verbose_level: i32, message: &str) {
    if tracee.verbose < verbose_level {
        return;
    }
    crate::note!(
        crate::note::Severity::Info,
        crate::note::Origin::Internal,
        "vpid {}: {}: {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {:#x} [{:#x}, {:?}]",
        tracee.vpid,
        message,
        stringify_sysnum(get_sysnum(tracee, RegVersion::Current)),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg3),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg4),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg5),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg6),
        peek_reg(tracee, RegVersion::Current, Reg::SysargResult),
        peek_reg(tracee, RegVersion::Current, Reg::StackPointer),
        get_abi(tracee),
    );
}

pub fn get_systrap_size(_tracee: &Tracee) -> Word {
    crate::arch::SYSTRAP_SIZE
}
