//! execve(2) sysenter translation — port of execve/enter.c.
//!
//! Rewrites the tracee's execve so it launches the embedded PRoot loader
//! (or QEMU / a script interpreter), collecting the ELF `LoadInfo` that
//! `exit.rs::transfer_load_script` will hand to the loader.

use std::os::unix::io::AsRawFd;
use std::sync::Mutex;

use crate::execve::aoxp::{
    fetch_array_of_xpointers, push_array_of_xpointers, read_xpointee_as_string,
    resize_array_of_xpointers, write_xpointee_string, write_xpointees,
};
use crate::execve::elf::{
    ET_DYN, ET_EXEC, ElfHeader, PF_R, PF_W, PF_X, PT_GNU_STACK, PT_INTERP, PT_LOAD, ProgramHeader,
    is_host_elf, iterate_program_headers, open_elf,
};
use crate::execve::ldso::{ldso_env_passthru, rebuild_host_ldso_paths};
use crate::execve::shebang::expand_shebang;
use crate::execve::{ExecveProcExeState, LoadInfo, Mapping, is_notification_ptraced_load_done};
use crate::fpath::FixedPath;
use crate::syscall::{get_sysarg_path, set_sysarg_path};
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::reg::{Reg, set_sysnum, sysarg};
use crate::{HOST_ROOTFS, Word};

/// Loader ELF embedded at build time (see build.rs).
const LOADER_EXE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/loader.exe"));

fn page_size() -> Word {
    static PAGE: Mutex<Word> = Mutex::new(0);
    let mut g = PAGE.lock().unwrap();
    if *g == 0 {
        let v = crate::sys::sysconf(libc::_SC_PAGESIZE);
        *g = if v > 0 { v as Word } else { 0x1000 };
    }
    *g
}

/// `add_mapping()` — turn a PT_LOAD phdr into one or two `Mapping`s
/// (file-backed part + anonymous BSS tail).
fn add_mapping(load_info: &mut LoadInfo, elf_header: &ElfHeader, ph: &ProgramHeader) -> i32 {
    let page = page_size();
    let mask = !(page - 1);

    let vaddr = ph.p_vaddr(elf_header);
    let filesz = ph.p_filesz(elf_header);
    let memsz = ph.p_memsz(elf_header);
    let flags = ph.p_flags(elf_header) as u32;
    let offset = ph.p_offset(elf_header);

    let start_address = vaddr & mask;
    let end_address = (vaddr + filesz + page) & mask;

    let prot = (if flags & PF_R != 0 {
        libc::PROT_READ
    } else {
        0
    } | if flags & PF_W != 0 {
        libc::PROT_WRITE
    } else {
        0
    } | if flags & PF_X != 0 {
        libc::PROT_EXEC
    } else {
        0
    }) as Word;

    let mut m = Mapping {
        fd: Word::MAX, // -1, unknown yet
        offset: offset & mask,
        addr: start_address,
        length: end_address - start_address,
        flags: (libc::MAP_PRIVATE | libc::MAP_FIXED) as Word,
        prot,
        clear_length: 0,
    };

    if memsz > filesz {
        m.clear_length = end_address - vaddr - filesz;
        let anon_start = end_address;
        let anon_end = (vaddr + memsz + page) & mask;
        load_info.mappings.push(m);
        if anon_end > anon_start {
            load_info.mappings.push(Mapping {
                fd: Word::MAX,
                offset: 0,
                addr: anon_start,
                length: anon_end - anon_start,
                clear_length: 0,
                flags: (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as Word,
                prot,
            });
        }
    } else {
        load_info.mappings.push(m);
    }
    0
}

/// `add_interp()` — record the PT_INTERP interpreter as a nested LoadInfo.
fn add_interp(
    tracee: &mut Tracee,
    fd: i32,
    load_info: &mut LoadInfo,
    elf_header: &ElfHeader,
    ph: &ProgramHeader,
) -> i32 {
    if load_info.interp.is_some() {
        return -libc::EINVAL;
    }
    let filesz = ph.p_filesz(elf_header);
    let offset = ph.p_offset(elf_header);

    let mut buf = vec![0u8; filesz as usize + 1];
    let n = crate::sys::pread(fd, &mut buf[..filesz as usize], offset as i64);
    if n != filesz as isize {
        return -libc::EACCES;
    }
    if let Some(nul) = buf.iter().position(|b| *b == 0) {
        buf.truncate(nul);
    }

    // Under QEMU, the interpreter path is relative to /host-rootfs.
    let mut user_path = buf;
    if tracee.qemu.is_some() && user_path.first() == Some(&b'/') {
        let mut v = HOST_ROOTFS.as_bytes().to_vec();
        v.extend_from_slice(&user_path);
        user_path = v;
    }

    let mut host_path = FixedPath::new();
    let status =
        crate::execve::shebang::translate_and_check_exec(tracee, &mut host_path, &user_path);
    if status < 0 {
        return status;
    }

    load_info.interp = Some(Box::new(LoadInfo {
        host_path: String::from_utf8_lossy(host_path.as_bytes()).into_owned(),
        user_path: String::from_utf8_lossy(&user_path).into_owned(),
        raw_path: String::new(),
        mappings: Vec::new(),
        elf_header: crate::sys::zeroed(),
        needs_executable_stack: false,
        interp: None,
    }));
    0
}

/// `extract_load_info()` — fill `load_info` (mappings, interp, stack flags)
/// from its `host_path` ELF file.
fn extract_load_info(tracee: &mut Tracee, load_info: &mut LoadInfo) -> i32 {
    let (fd, header) = match open_elf(load_info.host_path.as_bytes()) {
        Ok(x) => x,
        Err(e) => return e,
    };
    load_info.elf_header = header;

    let mut status = 0;
    match header.e_type() {
        t if t == ET_EXEC || t == ET_DYN => {}
        _ => status = -libc::EINVAL,
    }
    if status == 0 {
        // Iterate program headers; `error` captures callback failures.
        let mut error: i32 = 0;
        status = iterate_program_headers(fd, &header, |eh, ph| {
            match ph.p_type(eh) as u32 {
                PT_LOAD => {
                    error = add_mapping(load_info, eh, ph);
                }
                PT_INTERP => {
                    error = add_interp(tracee, fd, load_info, eh, ph);
                }
                PT_GNU_STACK => {
                    load_info.needs_executable_stack |= (ph.p_flags(eh) as u32) & PF_X != 0;
                }
                _ => {}
            }
            if error < 0 { error } else { 0 }
        });
        if status == 0 && error < 0 {
            status = error;
        }
    }
    crate::sys::close(fd);
    status
}

/// `add_load_base()`.
fn add_load_base(load_info: &mut LoadInfo, load_base: Word) {
    for m in load_info.mappings.iter_mut() {
        m.addr = m.addr.wrapping_add(load_base);
    }
    load_info.elf_header.set_entry_bias(load_base);
}

/// `compute_load_addresses()` — fixed PIC load addresses (no ASLR, like C).
fn compute_load_addresses(tracee: &mut Tracee) {
    let load_info = match tracee.load_info.as_deref_mut() {
        Some(l) => l,
        None => return,
    };
    let class32 = load_info.elf_header.is_class32();
    if load_info.elf_header.is_position_independent()
        && load_info.mappings.first().map_or(0, |m| m.addr) == 0
    {
        if class32 {
            add_load_base(load_info, crate::arch::EXEC_PIC_ADDRESS_32);
        } else {
            add_load_base(load_info, crate::arch::EXEC_PIC_ADDRESS);
        }
    }
    let interp = match load_info.interp.as_deref_mut() {
        Some(i) => i,
        None => return,
    };
    if interp.elf_header.is_position_independent()
        && interp.mappings.first().map_or(0, |m| m.addr) == 0
    {
        if class32 {
            add_load_base(interp, crate::arch::INTERP_PIC_ADDRESS_32);
        } else {
            add_load_base(interp, crate::arch::INTERP_PIC_ADDRESS);
        }
    }
}

/// `expand_runner()` — splice the QEMU runner into argv/envp.
fn expand_runner(tracee: &mut Tracee, host_path: &mut FixedPath, user_path: &mut FixedPath) -> i32 {
    let mut envp = match fetch_array_of_xpointers(tracee, sysarg(3), 0) {
        Ok(e) => e,
        Err(e) => return e,
    };

    if !is_host_elf(tracee, host_path.as_bytes()) {
        if std::env::var_os("PROOT_USE_LOADER_FOR_QEMU").is_none() {
            tracee.skip_proot_loader = true;
        }

        let mut argv = match fetch_array_of_xpointers(tracee, sysarg(2), 0) {
            Ok(a) => a,
            Err(e) => return e,
        };
        let argv0 = match read_xpointee_as_string(tracee, &mut argv, 0) {
            Ok(Some(a)) => a,
            Ok(None) => Vec::new(),
            Err(e) => return e,
        };

        let qemu = tracee.qemu.clone().unwrap();
        // C stores qemu as a NULL-terminated array; `nb_qemu_args` =
        // array_length - 1 = every real argument.  Our Vec has no
        // terminator, so it is just `len()`.
        let nb_qemu_args = qemu.len();
        if resize_array_of_xpointers(&mut argv, 1, nb_qemu_args as isize + 2) < 0 {
            return -libc::ENOMEM;
        }
        for (i, arg) in qemu.iter().take(nb_qemu_args).enumerate() {
            write_xpointee_string(&mut argv, i, arg.as_bytes());
        }
        let i = nb_qemu_args;
        write_xpointees(&mut argv, i, &[b"-0", &argv0, user_path.as_bytes()]);

        let status = ldso_env_passthru(tracee, &mut envp, &mut argv, "-E", "-U", i);
        if status < 0 {
            return status;
        }
        let status = push_array_of_xpointers(tracee, &mut argv, Reg::Sysarg2);
        if status < 0 {
            return status;
        }

        host_path.set(qemu[0].as_bytes());
        if tracee.skip_proot_loader {
            user_path.set(host_path.as_bytes());
        } else {
            let mut v = HOST_ROOTFS.as_bytes().to_vec();
            v.extend_from_slice(host_path.as_bytes());
            user_path.set(&v);
        }
    }

    let status = rebuild_host_ldso_paths(tracee, host_path.as_bytes(), &mut envp);
    if status < 0 {
        return status;
    }
    push_array_of_xpointers(tracee, &mut envp, Reg::Sysarg3)
}

/// `extract_loader()` — write the embedded loader ELF to a temp file and
/// return its path (through /proc/self/fd so it survives cleanup ordering).
fn extract_loader(tracee: &Tracee) -> Option<String> {
    let (mut file, _path) = crate::path::temp::open_temp_file("prooted")?;
    use std::io::Write;
    if file.write_all(LOADER_EXE).is_err() {
        crate::note!(
            Some(tracee),
            crate::note::Severity::Error,
            crate::note::Origin::System,
            "can't write the loader"
        );
        return None;
    }
    crate::sys::fchmod(file.as_raw_fd(), libc::S_IRUSR | libc::S_IXUSR);
    let mut path = FixedPath::new();
    if crate::path::readlink_proc_pid_fd(std::process::id() as i32, file.as_raw_fd(), &mut path)
        .is_err()
    {
        crate::note!(
            Some(tracee),
            crate::note::Severity::Error,
            crate::note::Origin::Internal,
            "can't retrieve loader path (/proc/self/fd/)"
        );
        return None;
    }
    let c = std::ffi::CString::new(path.as_bytes()).ok()?;
    if crate::sys::access(&c, libc::X_OK) < 0 {
        crate::note!(
            Some(tracee),
            crate::note::Severity::Error,
            crate::note::Origin::Internal,
            "it seems the current temporary directory ({}) is mounted with no execution permission.",
            crate::path::temp::get_temp_directory()
        );
        return None;
    }
    if tracee.verbose >= 2 {
        crate::note!(
            Some(tracee),
            crate::note::Severity::Info,
            crate::note::Origin::Internal,
            "loader: {}",
            path
        );
    }
    Some(path.to_string())
}

/// `get_loader_path()` — $PROOT_LOADER override, else the extracted
/// embedded loader (cached).
fn get_loader_path(tracee: &Tracee) -> Option<String> {
    static LOADER_PATH: Mutex<Option<String>> = Mutex::new(None);
    if let Ok(p) = std::env::var("PROOT_LOADER") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    let mut g = LOADER_PATH.lock().unwrap();
    if g.is_none() {
        *g = extract_loader(tracee);
    }
    g.clone()
}

/// `translate_execve_enter()`.
pub fn translate_execve_enter(tracee: &mut Tracee) -> i32 {
    if is_notification_ptraced_load_done(tracee) {
        tracee.as_ptracee.ignore_loader_syscalls = false;
        set_sysnum(tracee, Sysnum::Void);
        return 0;
    }

    let mut user_path = FixedPath::new();
    let mut status = get_sysarg_path(tracee, &mut user_path, Reg::Sysarg1);
    if status < 0 {
        return status;
    }
    let raw_path = user_path.clone();

    let mut host_path = FixedPath::new();
    status = match expand_shebang(tracee, &mut host_path, &mut user_path) {
        Ok(s) => s,
        Err(e) => {
            // The kernel reports -EACCES for directories.
            return if e == -libc::EISDIR { -libc::EACCES } else { e };
        }
    };

    // Keep the raw (pre-interpreter) path only when the effective program
    // differs — it fixes AT_EXECFN and /proc/pid/comm.
    let raw_path = if status == 0 && tracee.qemu.is_none() {
        None
    } else {
        Some(raw_path)
    };

    tracee.host_exe = Some(host_path.to_string());

    // Compute the new /proc/self/exe (guest side): extensions may
    // substitute it, else it is the detranslated host path.
    let mut proc_exe = ExecveProcExeState {
        host_path: host_path.clone(),
        guest_path: FixedPath::new(),
        substituted: false,
    };
    let ext_status = crate::extension::notify(
        tracee,
        &mut crate::extension::Event::ExecveProcExe {
            state: &mut proc_exe,
        },
    );
    let (new_exe, ok) = if ext_status >= 0 && proc_exe.substituted {
        (proc_exe.guest_path.clone(), true)
    } else {
        let mut p = host_path.clone();
        let ok = crate::path::detranslate_path(tracee, &mut p, None).is_ok();
        (p, ok)
    };
    tracee.new_exe = if ok { Some(new_exe.to_string()) } else { None };

    tracee.skip_proot_loader = false;
    if tracee.qemu.is_some() {
        status = expand_runner(tracee, &mut host_path, &mut user_path);
        if status < 0 {
            return status;
        }
    }

    tracee.load_info = None;

    if tracee.skip_proot_loader {
        if let Ok(mut heap) = tracee.heap.try_borrow_mut() {
            heap.disabled = true;
        }
        return set_sysarg_path(tracee, host_path.as_bytes(), Reg::Sysarg1);
    }

    let mut load_info = Box::new(LoadInfo {
        host_path: host_path.to_string(),
        user_path: user_path.to_string(),
        raw_path: match &raw_path {
            Some(r) => r.to_string(),
            None => user_path.to_string(),
        },
        mappings: Vec::new(),
        elf_header: crate::sys::zeroed(),
        needs_executable_stack: false,
        interp: None,
    });

    status = extract_load_info(tracee, &mut load_info);
    if status < 0 {
        tracee.load_info = None;
        return status;
    }

    if load_info.interp.is_some() {
        let mut interp = load_info.interp.take().unwrap();
        status = extract_load_info(tracee, &mut interp);
        if status < 0 {
            return status;
        }
        // An ELF interpreter is supposed to be standalone.
        if interp.interp.is_some() {
            interp.interp = None;
        }
        load_info.interp = Some(interp);
    }

    tracee.load_info = Some(load_info);
    compute_load_addresses(tracee);

    let loader_path = match get_loader_path(tracee) {
        Some(p) => p,
        None => return -libc::ENOENT,
    };

    status = set_sysarg_path(tracee, loader_path.as_bytes(), Reg::Sysarg1);
    if status < 0 {
        return status;
    }

    // Hide the loader's own syscalls from nested ptracers.
    tracee.as_ptracee.ignore_loader_syscalls = true;
    0
}
