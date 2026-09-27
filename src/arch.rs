//! Host-architecture constants and guest-ABI handling.
//!
//! Only the pieces the generic code needs are exposed here; register layout
//! details live in `tracee::reg` and syscall-number tables in `sysnum`.

use crate::Word;

/// Syscall number PRoot substitutes when it answers a syscall itself
/// (`PR_void`).  On x86_64 the avoider is negative so the kernel cancels the
/// syscall outright instead of executing it.
pub const SYSCALL_AVOIDER: Word = (-2i64) as Word;

/// Size in bytes of the instruction that triggers a syscall-stop
/// (`syscall`/`sysenter` on x86).
pub const SYSTRAP_SIZE: Word = 2;

/// Bytes below the stack pointer a leaf function may legally use; PRoot must
/// not scribble there when allocating tracee memory during sysenter.
pub const RED_ZONE_SIZE: Word = 128;

/// Fixed text address the loader ELF is linked at.
pub const LOADER_ADDRESS: u64 = 0x6000_0000_0000;

/// Load base for position-independent guest executables.
pub const EXEC_PIC_ADDRESS: u64 = 0x5000_0000_0000;

/// Load base for position-independent ELF interpreters.
pub const INTERP_PIC_ADDRESS: u64 = 0x6f00_0000_0000;

/// 32-bit counterparts used by the optional -m32 loader.
pub const EXEC_PIC_ADDRESS_32: u64 = 0x0f00_0000;
pub const INTERP_PIC_ADDRESS_32: u64 = 0xaf00_0000;

/// e_machine values treated as "host" binaries under QEMU.
pub const HOST_ELF_MACHINE: &[u16] = &[62, 3, 6];

/// AUDIT_ARCH_* tokens used in the seccomp filter, paired with the ABIs each
/// section covers.
#[derive(Copy, Clone)]
pub struct SeccompArch {
    pub value: u32,
    pub abis: &'static [crate::sysnum::Abi],
}

pub const SECCOMP_ARCHS: &[SeccompArch] = &[
    SeccompArch {
        value: AUDIT_ARCH_X86_64,
        abis: &[crate::sysnum::Abi::Default, crate::sysnum::Abi::Abi3],
    },
    SeccompArch {
        value: AUDIT_ARCH_I386,
        abis: &[crate::sysnum::Abi::Abi2],
    },
];

pub const AUDIT_ARCH_I386: u32 = 0x4000_0003; // EM_386 | __AUDIT_ARCH_LE|64? no: 0x40000000|3
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E; // EM_X86_64|__AUDIT_ARCH_64BIT|LE

/// Offsets of st_uid/st_gid inside the *32-bit* `struct stat` layout.
pub const OFFSETOF_STAT_UID_32: usize = 24;
pub const OFFSETOF_STAT_GID_32: usize = 28;
