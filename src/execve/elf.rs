//! ELF structures and helpers — port of execve/elf.c.

use std::os::unix::io::RawFd;

use crate::tracee::Tracee;

pub const EI_NIDENT: usize = 16;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ElfHeader32 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ElfHeader64 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Copy, Clone)]
pub union ElfHeader {
    pub class32: ElfHeader32,
    pub class64: ElfHeader64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgramHeader32 {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgramHeader64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Copy, Clone)]
pub union ProgramHeader {
    pub class32: ProgramHeader32,
    pub class64: ProgramHeader64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DynamicEntry32 {
    pub d_tag: i32,
    pub d_val: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DynamicEntry64 {
    pub d_tag: i64,
    pub d_val: u64,
}

#[derive(Copy, Clone)]
pub union DynamicEntry {
    pub class32: DynamicEntry32,
    pub class64: DynamicEntry64,
}

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474_e551;

pub const DT_STRTAB: i64 = 5;
pub const DT_RPATH: i64 = 15;
pub const DT_RUNPATH: i64 = 29;

impl ElfHeader {
    #[inline]
    pub fn ident(&self, index: usize) -> u8 {
        unsafe { self.class32.e_ident[index] }
    }
    #[inline]
    pub fn is_class32(&self) -> bool {
        self.ident(4) == 1
    }
    #[inline]
    pub fn is_class64(&self) -> bool {
        self.ident(4) == 2
    }
    /// `ELF_FIELD()` — 64-bit when class64.
    #[inline]
    pub fn field64(&self, f32: impl Fn(&ElfHeader32) -> u32, f64: impl Fn(&ElfHeader64) -> u64) -> u64 {
        unsafe {
            if self.is_class64() {
                f64(&self.class64)
            } else {
                f32(&self.class32) as u64
            }
        }
    }
    pub fn e_type(&self) -> u16 {
        unsafe { self.class64.e_type }
    }
    pub fn e_machine(&self) -> u16 {
        unsafe { self.class64.e_machine }
    }
    pub fn e_entry(&self) -> u64 {
        self.field64(|h| h.e_entry, |h| h.e_entry)
    }
    pub fn e_phoff(&self) -> u64 {
        self.field64(|h| h.e_phoff, |h| h.e_phoff)
    }
    pub fn e_phentsize(&self) -> u16 {
        unsafe { self.class64.e_phentsize }
    }
    pub fn e_phnum(&self) -> u16 {
        unsafe { self.class64.e_phnum }
    }
    pub fn is_position_independent(&self) -> bool {
        self.e_type() == ET_DYN
    }
}

impl ProgramHeader {
    #[inline]
    pub fn field(&self, ehdr: &ElfHeader, f32: impl Fn(&ProgramHeader32) -> u32, f64: impl Fn(&ProgramHeader64) -> u64) -> u64 {
        unsafe {
            if ehdr.is_class64() {
                f64(&self.class64)
            } else {
                f32(&self.class32) as u64
            }
        }
    }
    pub fn p_type(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_type, |p| p.p_type as u64)
    }
    pub fn p_offset(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_offset, |p| p.p_offset)
    }
    pub fn p_vaddr(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_vaddr, |p| p.p_vaddr)
    }
    pub fn p_filesz(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_filesz, |p| p.p_filesz)
    }
    pub fn p_memsz(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_memsz, |p| p.p_memsz)
    }
    pub fn p_flags(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_flags, |p| p.p_flags as u64)
    }
}

impl DynamicEntry {
    #[inline]
    pub fn field(&self, ehdr: &ElfHeader, f32: impl Fn(&DynamicEntry32) -> u32, f64: impl Fn(&DynamicEntry64) -> u64) -> u64 {
        unsafe {
            if ehdr.is_class64() {
                f64(&self.class64)
            } else {
                f32(&self.class32) as u64
            }
        }
    }
    pub fn d_tag(&self, ehdr: &ElfHeader) -> i64 {
        self.field(ehdr, |d| d.d_tag as u32, |d| d.d_tag as u64) as i64
    }
    pub fn d_val(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |d| d.d_val, |d| d.d_val)
    }
}

pub fn known_phentsize(header: &ElfHeader, size: u64) -> bool {
    (header.is_class32() && size == std::mem::size_of::<ProgramHeader32>() as u64)
        || (header.is_class64() && size == std::mem::size_of::<ProgramHeader64>() as u64)
}

/// `open_elf()` — open `t_path` and read+validate its ELF header.  On success
/// returns Ok((fd, header)); the fd is left open at offset 0.
pub fn open_elf(t_path: &[u8]) -> Result<(RawFd, ElfHeader), i32> {
    let c = std::ffi::CString::new(t_path).map_err(|_| -libc::EINVAL)?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(-crate::path::errno());
    }
    let mut ehdr: ElfHeader = unsafe { std::mem::zeroed() };
    let n = unsafe {
        libc::read(
            fd,
            &mut ehdr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<ElfHeader>(),
        )
    };
    if n < std::mem::size_of::<ElfHeader32>() as isize {
        unsafe { libc::close(fd) };
        return Err(-libc::ENOEXEC);
    }
    if ehdr.ident(0) != 0x7f || ehdr.ident(1) != b'E' || ehdr.ident(2) != b'L' || ehdr.ident(3) != b'F'
    {
        unsafe { libc::close(fd) };
        return Err(-libc::ENOEXEC);
    }
    if !ehdr.is_class32() && !ehdr.is_class64() {
        unsafe { libc::close(fd) };
        return Err(-libc::ENOEXEC);
    }
    Ok((fd, ehdr))
}

/// `is_host_elf()` — whether `t_path` is an ELF for the *host* machine
/// (relevant under QEMU mixed mode).
pub fn is_host_elf(tracee: &Tracee, t_path: &[u8]) -> bool {
    match open_elf(t_path) {
        Ok((fd, ehdr)) => {
            unsafe { libc::close(fd) };
            crate::arch::HOST_ELF_MACHINE.contains(&ehdr.e_machine())
        }
        Err(_) => {
            let _ = tracee;
            false
        }
    }
}

/// `iterate_program_headers()` — walk program headers of `fd`, calling `cb`
/// on each.  The callback returns <0 to abort iteration.
pub fn iterate_program_headers(
    fd: RawFd,
    elf_header: &ElfHeader,
    mut cb: impl FnMut(&ElfHeader, &ProgramHeader) -> i32,
) -> i32 {
    let phoff = elf_header.e_phoff();
    let phentsize = elf_header.e_phentsize() as u64;
    let phnum = elf_header.e_phnum() as u64;
    if !known_phentsize(elf_header, phentsize) {
        return -libc::EINVAL;
    }
    for i in 0..phnum {
        let mut phdr: ProgramHeader = unsafe { std::mem::zeroed() };
        let off = phoff + i * phentsize;
        let n = unsafe {
            libc::pread(
                fd,
                &mut phdr as *mut _ as *mut libc::c_void,
                phentsize as usize,
                off as i64,
            )
        };
        if n != phentsize as isize {
            return -libc::EIO;
        }
        let status = cb(elf_header, &phdr);
        if status != 0 {
            return status;
        }
    }
    0
}
