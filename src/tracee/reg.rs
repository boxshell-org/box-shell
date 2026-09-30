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

fn reg_read(regs: &Regs, off: usize) -> u64 {
    crate::sys::as_bytes(regs)[off..off + 8]
        .try_into()
        .map(u64::from_ne_bytes)
        .unwrap_or(0)
}
fn reg_write(regs: &mut Regs, off: usize, v: u64) {
    crate::sys::as_bytes_mut(regs)[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

/// `peek_reg()` — read the cached value of `reg` in `version`.
pub fn peek_reg(tracee: &Tracee, version: RegVersion, reg: Reg) -> Word {
    let off = reg_offsets(tracee, version)[reg as usize];
    let mut v = reg_read(&tracee.regs[version.idx()], off);
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
    reg_write(&mut tracee.regs[RegVersion::Current.idx()], off, value);
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
    let status = crate::sys::ptrace(
        crate::ptrace::ptc::PTRACE_GETREGS as u32,
        tracee.pid,
        0,
        &mut tracee.regs[RegVersion::Current.idx()] as *mut _ as usize,
    );
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
                let v = reg_read(&tracee.regs[from.idx()], src_off);
                reg_write(&mut tracee.regs[RegVersion::Current.idx()], dst_off, v);
            }
        }
        // including_sysnum is a no-op on x86_64: orig_rax is part of the
        // register set pushed by PTRACE_SETREGS anyway.
        let _ = including_sysnum;
        let status = crate::sys::ptrace(
            crate::ptrace::ptc::PTRACE_SETREGS as u32,
            tracee.pid,
            0,
            &tracee.regs[RegVersion::Current.idx()] as *const _ as usize,
        );
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
        get_sysnum(tracee, RegVersion::Current).name(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> Tracee {
        Tracee::default()
    }

    #[test]
    fn regversion_idx_distinct() {
        let idxs = [
            RegVersion::Current.idx(),
            RegVersion::Original.idx(),
            RegVersion::Modified.idx(),
            RegVersion::OriginalSeccompRewrite.idx(),
        ];
        let mut sorted = idxs.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), RegVersion::COUNT);
    }

    #[test]
    fn sysarg_index_maps_one_based() {
        assert_eq!(sysarg(1), Reg::Sysarg1);
        assert_eq!(sysarg(6), Reg::Sysarg6);
        assert_eq!(sysarg(4), Reg::Sysarg4);
    }

    #[test]
    #[should_panic]
    fn sysarg_rejects_zero() {
        let _ = sysarg(0);
    }

    #[test]
    fn poke_peek_roundtrip_x86_64() {
        let mut t = mk();
        poke_reg(&mut t, Reg::Sysarg1, 0xDEAD_BEEF);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg1), 0xDEAD_BEEF);
        assert!(t.regs_were_changed);
        // Sysarg1 lives in rdi on x86_64.
        assert_eq!(t.regs[RegVersion::Current.idx()].rdi, 0xDEAD_BEEF);
        // Other banks unaffected.
        assert_eq!(peek_reg(&t, RegVersion::Original, Reg::Sysarg1), 0);
    }

    #[test]
    fn poke_same_value_is_noop() {
        let mut t = mk();
        poke_reg(&mut t, Reg::StackPointer, 7);
        t.regs_were_changed = false;
        poke_reg(&mut t, Reg::StackPointer, 7);
        assert!(!t.regs_were_changed);
    }

    #[test]
    fn abi_detection_from_cs() {
        let mut t = mk();
        // cs=0x33,ds=0 -> Default (64-bit).
        t.regs[RegVersion::Original.idx()].cs = 0x33;
        assert_eq!(get_abi(&t), Abi::Default);
        // cs=0x23 -> i386 ABI.
        t.regs[RegVersion::Original.idx()].cs = 0x23;
        assert_eq!(get_abi(&t), Abi::Abi2);
        // cs=0x33 + ds=0x2B -> x32 ABI.
        t.regs[RegVersion::Original.idx()].cs = 0x33;
        t.regs[RegVersion::Original.idx()].ds = 0x2B;
        assert_eq!(get_abi(&t), Abi::Abi3);
    }

    #[test]
    fn is_32on64_and_word_size() {
        let mut t = mk();
        t.regs[RegVersion::Current.idx()].cs = 0x33;
        assert!(!is_32on64_mode(&t));
        assert_eq!(sizeof_word(&t), 8);
        t.regs[RegVersion::Current.idx()].cs = 0x23;
        assert!(is_32on64_mode(&t));
        assert_eq!(sizeof_word(&t), 4);
        t.regs[RegVersion::Current.idx()].cs = 0x33;
        t.regs[RegVersion::Current.idx()].ds = 0x2B;
        assert!(is_32on64_mode(&t)); // x32
    }

    #[test]
    fn peek_masks_high32_in_32bit_mode() {
        let mut t = mk();
        t.regs[RegVersion::Current.idx()].cs = 0x23;
        // i386 Sysarg2 is rcx — set a >32-bit value there directly.
        t.regs[RegVersion::Current.idx()].rcx = 0x1_0000_00AB;
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg2), 0xAB);
    }

    #[test]
    fn i386_abi_uses_i386_offsets() {
        let mut t = mk();
        t.regs[RegVersion::Current.idx()].cs = 0x23;
        poke_reg(&mut t, Reg::Sysarg1, 0x1234);
        // Sysarg1 is ebx under i386 conventions.
        assert_eq!(t.regs[RegVersion::Current.idx()].rbx, 0x1234);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg1), 0x1234);
    }

    #[test]
    fn save_current_regs_copies_bank() {
        let mut t = mk();
        poke_reg(&mut t, Reg::Sysarg3, 42);
        save_current_regs(&mut t, RegVersion::Modified);
        assert_eq!(peek_reg(&t, RegVersion::Modified, Reg::Sysarg3), 42);
        // Saving to Original clears the dirty flag.
        assert!(t.regs_were_changed);
        save_current_regs(&mut t, RegVersion::Original);
        assert!(!t.regs_were_changed);
        assert_eq!(peek_reg(&t, RegVersion::Original, Reg::Sysarg3), 42);
    }

    #[test]
    fn get_set_sysnum_translates() {
        let mut t = mk();
        t.regs[RegVersion::Original.idx()].cs = 0x33;
        t.regs[RegVersion::Current.idx()].cs = 0x33;
        set_sysnum(&mut t, Sysnum::openat);
        assert_eq!(t.regs[RegVersion::Current.idx()].orig_rax, 257);
        // get_sysnum reads the requested bank; Current holds the write.
        assert_eq!(get_sysnum(&t, RegVersion::Current), Sysnum::openat);
        // Original bank is untouched until save_current_regs.
        assert_eq!(get_sysnum(&t, RegVersion::Original), Sysnum::read);
        // i386 ABI: openat is 295.
        let mut t = mk();
        t.regs[RegVersion::Original.idx()].cs = 0x23;
        t.regs[RegVersion::Current.idx()].cs = 0x23;
        set_sysnum(&mut t, Sysnum::openat);
        assert_eq!(t.regs[RegVersion::Current.idx()].orig_rax, 295);
    }

    #[test]
    fn fetch_push_regs_fail_without_ptrace_target() {
        // pid 0 is invalid for ptrace GETREGS -> error, not panic.
        let mut t = mk();
        assert!(fetch_regs(&mut t) < 0);
        // push_regs with no changes is a no-op success.
        t.regs_were_changed = false;
        assert_eq!(push_regs(&mut t), 0);
        // Dirty regs on a dead pid -> ptrace error.
        poke_reg(&mut t, Reg::Sysarg1, 1);
        assert!(push_regs(&mut t) < 0);
    }

    #[test]
    fn systrap_size_is_positive() {
        assert_eq!(get_systrap_size(&mk()), crate::arch::SYSTRAP_SIZE);
    }
}
