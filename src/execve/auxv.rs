//! ELF auxiliary vectors — port of execve/auxv.c.

use crate::Word;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_word, poke_word};
use crate::tracee::reg::{Reg, RegVersion, peek_reg, sizeof_word};

pub const AT_NULL: Word = 0;
pub const AT_IGNORE: Word = 1;
pub const AT_PHENT: Word = 4;
pub const AT_PHNUM: Word = 5;
pub const AT_PAGESZ: Word = 6;
pub const AT_BASE: Word = 7;
pub const AT_FLAGS: Word = 8;
pub const AT_ENTRY: Word = 9;
pub const AT_UID: Word = 11;
pub const AT_EUID: Word = 12;
pub const AT_GID: Word = 13;
pub const AT_EGID: Word = 14;
pub const AT_HWCAP: Word = 16;
pub const AT_CLKTCK: Word = 17;
pub const AT_SECURE: Word = 23;
pub const AT_RANDOM: Word = 25;
pub const AT_EXECFN: Word = 31;
pub const AT_SYSINFO: Word = 32;
pub const AT_SYSINFO_EHDR: Word = 33;

#[derive(Copy, Clone, Default)]
pub struct ElfAuxVector {
    pub atype: Word,
    pub value: Word,
}

/// `get_elf_aux_vectors_address()` — locate the auxv table on the initial
/// stack right after a successful execve (valid only in execve sysexit).
/// Returns 0 on error.
pub fn get_elf_aux_vectors_address(tracee: &Tracee) -> Word {
    let w = sizeof_word(tracee) as Word;
    let mut address = peek_reg(tracee, RegVersion::Current, Reg::StackPointer);
    crate::sys::clear_errno();

    // argc, then argv[] + NULL.
    let argc = peek_word(tracee, address);
    if crate::sys::errno() != 0 {
        return 0;
    }
    address += (1 + argc + 1) * w;

    // envp[] + NULL.
    loop {
        let data = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return 0;
        }
        address += w;
        if data == 0 {
            break;
        }
    }
    address
}

/// `fetch_elf_aux_vectors()` — read the AT_NULL-terminated vector list.
pub fn fetch_elf_aux_vectors(tracee: &Tracee, address: Word) -> Option<Vec<ElfAuxVector>> {
    let w = sizeof_word(tracee) as Word;
    let mut address = address;
    let mut vectors = Vec::new();
    loop {
        crate::sys::clear_errno();
        let atype = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return None;
        }
        address += w;
        if atype == AT_NULL {
            break;
        }
        let value = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return None;
        }
        address += w;
        vectors.push(ElfAuxVector { atype, value });
    }
    vectors.push(ElfAuxVector {
        atype: AT_NULL,
        value: 0,
    });
    Some(vectors)
}

/// `push_elf_aux_vectors()` — write the vector list back to `address`.
pub fn push_elf_aux_vectors(tracee: &Tracee, vectors: &[ElfAuxVector], address: Word) -> i32 {
    let w = sizeof_word(tracee) as Word;
    let mut address = address;
    for v in vectors
        .iter()
        .chain(std::iter::once(&ElfAuxVector::default()))
    {
        crate::sys::clear_errno();
        poke_word(tracee, address, v.atype);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
        address += w;
        poke_word(tracee, address, v.value);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
        address += w;
        if v.atype == AT_NULL {
            break;
        }
    }
    0
}
