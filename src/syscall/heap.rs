//! Virtual heap — port of syscall/heap.c.  brk() is rewritten in place into
//! mmap/mremap against a private anonymous mapping at a controlled address.

use crate::Word;
use crate::arch::SYSCALL_AVOIDER;
use crate::sysnum::{Sysnum, detranslate_sysnum};
use crate::tracee::Tracee;
use crate::tracee::reg::{Reg, RegVersion, get_abi, get_sysnum, peek_reg, poke_reg, set_sysnum};

/// The size of the heap can be zero, unlike a memory mapping: the first page
/// of the heap mapping is discarded so an empty heap is representable.
fn heap_offset() -> Word {
    crate::sys::page_size()
}

#[derive(Default)]
pub struct Heap {
    pub base: Word,
    pub size: usize,
    pub disabled: bool,
}

impl Heap {
    /// `talloc_memdup` equivalent for the non-CLONE_VM fork case.
    pub fn clone_heap(&self) -> Heap {
        Heap {
            base: self.base,
            size: self.size,
            disabled: self.disabled,
        }
    }
}

/// `translate_brk_enter()`.
pub fn translate_brk_enter(tracee: &mut Tracee) {
    if tracee.heap.borrow().disabled {
        return;
    }
    let offset = heap_offset();
    let mut new_brk_address = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);

    // Allocate a new mapping for the emulated heap.
    if tracee.heap.borrow().base == 0 {
        // This tracee might be PRoot's first child before its first execve:
        // a non-zero argument then is suspicious.
        if new_brk_address != 0 {
            if tracee.verbose > 0 {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "process {} is doing suspicious brk()",
                    tracee.pid
                );
            }
            return;
        }

        // Put the heap as close to the BSS as possible — some programs
        // assume the gap stays small.  bss->addr + bss->length is already
        // page aligned per add_mapping() in execve::enter.
        if let Some(li) = &tracee.load_info {
            if let Some(bss) = li.mappings.last() {
                new_brk_address = bss.addr + bss.length;
            }
        }

        let sysnum = if detranslate_sysnum(get_abi(tracee), Sysnum::mmap2) != SYSCALL_AVOIDER {
            Sysnum::mmap2
        } else {
            Sysnum::mmap
        };

        set_sysnum(tracee, sysnum);
        poke_reg(tracee, Reg::Sysarg1, new_brk_address);
        poke_reg(tracee, Reg::Sysarg2, offset);
        poke_reg(
            tracee,
            Reg::Sysarg3,
            (libc::PROT_READ | libc::PROT_WRITE) as Word,
        );
        poke_reg(
            tracee,
            Reg::Sysarg4,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as Word,
        );
        poke_reg(tracee, Reg::Sysarg5, Word::MAX); // fd = -1
        poke_reg(tracee, Reg::Sysarg6, 0);
        return;
    }

    let base = tracee.heap.borrow().base;

    // The heap size can't be negative.
    if new_brk_address < base {
        set_sysnum(tracee, Sysnum::Void);
        return;
    }

    let new_heap_size = new_brk_address - base;
    let old_heap_size = tracee.heap.borrow().size as Word;

    // Actually resizing.
    set_sysnum(tracee, Sysnum::mremap);
    poke_reg(tracee, Reg::Sysarg1, base - offset);
    poke_reg(tracee, Reg::Sysarg2, old_heap_size + offset);
    poke_reg(tracee, Reg::Sysarg3, new_heap_size + offset);
    poke_reg(tracee, Reg::Sysarg4, 0);
    poke_reg(tracee, Reg::Sysarg5, 0);
}

/// `translate_brk_exit()`.
pub fn translate_brk_exit(tracee: &mut Tracee) {
    if tracee.heap.borrow().disabled {
        return;
    }
    let offset = heap_offset();

    let sysnum = get_sysnum(tracee, RegVersion::Modified);
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    let tracee_errno = result as i64;

    match sysnum {
        Sysnum::Void => {
            let r = tracee.heap.borrow().base + tracee.heap.borrow().size as Word;
            poke_reg(tracee, Reg::SysargResult, r);
        }
        Sysnum::mmap | Sysnum::mmap2 => {
            // mmap reports -errno; brk reports the previous value.
            if tracee_errno < 0 && tracee_errno > -4096 {
                poke_reg(tracee, Reg::SysargResult, 0);
                return;
            }
            let mut h = tracee.heap.borrow_mut();
            h.base = result + offset;
            h.size = 0;
            let r = h.base + h.size as Word;
            drop(h);
            poke_reg(tracee, Reg::SysargResult, r);
        }
        Sysnum::mremap => {
            let base = tracee.heap.borrow().base;
            let size = tracee.heap.borrow().size as Word;
            if (tracee_errno < 0 && tracee_errno > -4096) || base != result + offset {
                poke_reg(tracee, Reg::SysargResult, base + size);
                return;
            }
            let new_size = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg3) - offset;
            tracee.heap.borrow_mut().size = new_size as usize;
            let r = base + new_size;
            poke_reg(tracee, Reg::SysargResult, r);
        }
        Sysnum::brk => {
            // Confirmed legit pre-execve brk: stop emulating.
            if result == peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) {
                tracee.heap.borrow_mut().disabled = true;
            }
        }
        _ => unreachable!(),
    }
}
