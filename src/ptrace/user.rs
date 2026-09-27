//! 32↔64-bit `struct user` area conversions — port of ptrace/user.c
//! (x86_64-only section; other archs don't need it).

use crate::Word;

/// Number of registers in a 32-bit user area.
pub const USER32_NB_REGS: usize = 17;
/// Number of FP regs in a 32-bit user area.
pub const USER32_NB_FPREGS: usize = 27;

const USER32_REGS_OFFSET: usize = 0;
const USER32_REGS_SIZE: usize = USER32_NB_REGS * 4;
const USER32_FPVALID_OFFSET: usize = USER32_REGS_OFFSET + USER32_REGS_SIZE;
const USER32_I387_OFFSET: usize = USER32_FPVALID_OFFSET + 4;
const USER32_I387_SIZE: usize = USER32_NB_FPREGS * 4;
const USER32_TSIZE_OFFSET: usize = USER32_I387_OFFSET + USER32_I387_SIZE;
const USER32_DSIZE_OFFSET: usize = USER32_TSIZE_OFFSET + 4;
const USER32_SSIZE_OFFSET: usize = USER32_DSIZE_OFFSET + 4;
const USER32_START_CODE_OFFSET: usize = USER32_SSIZE_OFFSET + 4;
const USER32_START_STACK_OFFSET: usize = USER32_START_CODE_OFFSET + 4;
const USER32_SIGNAL_OFFSET: usize = USER32_START_STACK_OFFSET + 4;
const USER32_RESERVED_OFFSET: usize = USER32_SIGNAL_OFFSET + 4;
const USER32_AR0_OFFSET: usize = USER32_RESERVED_OFFSET + 4;
const USER32_FPSTATE_OFFSET: usize = USER32_AR0_OFFSET + 4;
const USER32_MAGIC_OFFSET: usize = USER32_FPSTATE_OFFSET + 4;
const USER32_COMM_OFFSET: usize = USER32_MAGIC_OFFSET + 4;
const USER32_COMM_SIZE: usize = 32;
const USER32_DEBUGREG_OFFSET: usize = USER32_COMM_OFFSET + USER32_COMM_SIZE;
const USER32_DEBUGREG_SIZE: usize = 8 * 4;

/// Index map 32-bit-user.regs[i] → 64-bit-user.regs[j].
const fn convert_user_regs_index(index: usize) -> usize {
    const MAPPING: [usize; USER32_NB_REGS] = [
        5,  /* ?bx */
        11, /* ?cx */
        12, /* ?dx */
        13, /* ?si */
        14, /* ?di */
        4,  /* ?bp */
        10, /* ?ax */
        23, /* ds */
        24, /* es */
        25, /* fs */
        26, /* gs */
        15, /* orig_?ax */
        16, /* ?ip */
        17, /* cs */
        18, /* eflags */
        19, /* ?sp */
        20, /* ss */
    ];
    MAPPING[index]
}

/// `offsetof(struct user, u_debugreg)` — the debugreg array sits after
/// the regs/fp fields; computed from libc::user.
const DEBUGREG64_OFFSET: usize = std::mem::offset_of!(libc::user, u_debugreg);

fn convert_user_debugreg_offset(offset: usize) -> usize {
    debug_assert!((USER32_DEBUGREG_OFFSET..USER32_DEBUGREG_OFFSET + USER32_DEBUGREG_SIZE)
        .contains(&offset));
    let index = (offset - USER32_DEBUGREG_OFFSET) / 4;
    DEBUGREG64_OFFSET + index * 8
}

/// `convert_user_offset()` — 32-bit user-area offset → 64-bit one;
/// -1 when invalid or unsupported.
pub fn convert_user_offset(offset: Word) -> Word {
    let offset = offset as usize;
    if offset < USER32_REGS_OFFSET + USER32_REGS_SIZE {
        if offset % 4 != 0 {
            return Word::MAX;
        }
        return (convert_user_regs_index(offset / 4) * 8) as Word;
    }
    let area = if offset == USER32_FPVALID_OFFSET {
        "fpvalid"
    } else if (USER32_I387_OFFSET..USER32_I387_OFFSET + USER32_I387_SIZE).contains(&offset) {
        "i387"
    } else if offset == USER32_TSIZE_OFFSET {
        "tsize"
    } else if offset == USER32_DSIZE_OFFSET {
        "dsize"
    } else if offset == USER32_SSIZE_OFFSET {
        "ssize"
    } else if offset == USER32_START_CODE_OFFSET {
        "start_code"
    } else if offset == USER32_START_STACK_OFFSET {
        "start_stack"
    } else if offset == USER32_SIGNAL_OFFSET {
        "signal"
    } else if offset == USER32_RESERVED_OFFSET {
        "reserved"
    } else if offset == USER32_AR0_OFFSET {
        "ar0"
    } else if offset == USER32_FPSTATE_OFFSET {
        "fpstate"
    } else if offset == USER32_MAGIC_OFFSET {
        "magic"
    } else if (USER32_COMM_OFFSET..USER32_COMM_OFFSET + USER32_COMM_SIZE).contains(&offset) {
        "comm"
    } else if (USER32_DEBUGREG_OFFSET..USER32_DEBUGREG_OFFSET + USER32_DEBUGREG_SIZE)
        .contains(&offset)
    {
        return convert_user_debugreg_offset(offset) as Word;
    } else {
        "<unknown>"
    };
    crate::note!(
        None,
        crate::note::Severity::Warning,
        crate::note::Origin::Internal,
        "ptrace user area '{}' not supported yet",
        area
    );
    Word::MAX
}

/// `convert_user_regs_struct()` — marshal a 32-bit user regs block to/from
/// a 64-bit `user_regs_struct` (held as a flat u64 slice).
pub fn convert_user_regs_struct(reverse: bool, user_regs64: &mut [u64], user_regs32: &mut [u32; USER32_NB_REGS]) {
    for index32 in 0..USER32_NB_REGS {
        let index64 = convert_user_regs_index(index32);
        if reverse {
            user_regs64[index64] = user_regs32[index32] as u64;
        } else {
            user_regs32[index32] = user_regs64[index64] as u32;
        }
    }
}
