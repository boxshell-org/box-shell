//! port_switch extension (`-p`) — port of
//! extension/port_switch/port_switch.c.
//!
//! Remaps bind/connect/sendto ports <1024 by +2000 so unprivileged
//! guests can claim "privileged" ports.  connect/sendto are only
//! rewritten for localhost destinations.

use crate::extension::Event;
use crate::sysnum::Sysnum;
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{get_sysnum, peek_reg, Reg, RegVersion};
use crate::tracee::Tracee;
use crate::Word;

const PORT_THRESHOLD: u16 = 1024;
const PORT_ADDITION: u16 = 2000;
const SOCKADDR_STORAGE_SIZE: usize = 128;

const AF_INET: u16 = libc::AF_INET as u16;
const AF_INET6: u16 = libc::AF_INET6 as u16;
const SYS_BIND: i32 = 1;
const SYS_CONNECT: i32 = 2;
const SYS_SENDTO: i32 = 11;

#[derive(Default)]
pub struct PortSwitch;

/// `is_localhost()` — AF_INET 127.0.0.1 or AF_INET6 ::1.
fn is_localhost(sa: &[u8]) -> bool {
    let family = u16::from_ne_bytes([sa[0], sa[1]]);
    match family {
        AF_INET => sa[4..8] == [127, 0, 0, 1],
        AF_INET6 => sa[8..24].iter().take(15).all(|&b| b == 0) && sa[23] == 1,
        _ => false,
    }
}

/// `mod_port()` — bump ports in [1,1024) by 2000 inside the sockaddr,
/// then write it back through the appropriate register/indirection.
fn mod_port(
    tracee: &mut Tracee,
    is_socketcall: bool,
    is_bind: bool,
    is_udp: bool,
    sa: &mut [u8],
    socketcall_args: Option<&mut [u64; 6]>,
) {
    let family = u16::from_ne_bytes([sa[0], sa[1]]);
    if family != AF_INET && family != AF_INET6 {
        return;
    }
    let port = u16::from_be_bytes([sa[2], sa[3]]);
    if port == 0 || port >= PORT_THRESHOLD {
        return;
    }
    let new_port = port + PORT_ADDITION;
    if is_bind {
        println!("\nATTENTION: A bind system call was requested on port: {}", port);
        println!("The port has been changed. If connecting from outside Termux, use: {}\n", new_port);
    }
    sa[2..4].copy_from_slice(&new_port.to_be_bytes());

    // sockaddr lives at SYSARG_5 for sendto, SYSARG_2 otherwise; for
    // socketcall it's behind arg[1]/arg[4] and the args array itself must
    // be written back too (unused slots are unchanged so this is a no-op
    // write, matching C).
    let (sa_addr, args) = match (is_socketcall, is_udp) {
        (true, true) => (socketcall_args.as_ref().unwrap()[4], Some(socketcall_args)),
        (false, true) => (peek_reg(tracee, RegVersion::Current, Reg::Sysarg5), None),
        (true, false) => (socketcall_args.as_ref().unwrap()[1], Some(socketcall_args)),
        (false, false) => (peek_reg(tracee, RegVersion::Current, Reg::Sysarg2), None),
    };
    // C passes `sizeof(in)` where `in` is a pointer — i.e. 8 bytes, which
    // covers family + port (+ 4 bytes of addr).  Match that exactly.
    write_data(tracee, sa_addr, &sa[..8]);
    if let Some(Some(a)) = args {
        let mut buf = [0u8; 48];
        for (i, v) in a.iter().enumerate() {
            buf[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
        }
        write_data(tracee, peek_reg(tracee, RegVersion::Current, Reg::Sysarg2), &buf);
    }
}

fn read_sockaddr(tracee: &Tracee, addr: Word) -> Option<[u8; SOCKADDR_STORAGE_SIZE]> {
    let mut sa = [0u8; SOCKADDR_STORAGE_SIZE];
    if read_data(tracee, &mut sa, addr) < 0 {
        return None;
    }
    Some(sa)
}

fn handle_sysenter_end(tracee: &mut Tracee) -> i32 {
    match get_sysnum(tracee, RegVersion::Original) {
        Sysnum::bind => {
            if let Some(mut sa) =
                read_sockaddr(tracee, peek_reg(tracee, RegVersion::Original, Reg::Sysarg2))
            {
                mod_port(tracee, false, true, false, &mut sa, None);
            }
            0
        }
        Sysnum::connect => {
            if let Some(mut sa) =
                read_sockaddr(tracee, peek_reg(tracee, RegVersion::Original, Reg::Sysarg2))
            {
                if is_localhost(&sa) {
                    mod_port(tracee, false, false, false, &mut sa, None);
                }
            }
            0
        }
        Sysnum::sendto => {
            // In connected mode the sockaddr arg is NULL — skip those.
            let addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg5);
            if addr != 0 {
                if let Some(mut sa) = read_sockaddr(tracee, addr) {
                    if is_localhost(&sa) {
                        mod_port(tracee, false, false, true, &mut sa, None);
                    }
                }
            }
            0
        }
        Sysnum::socketcall => {
            let call = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32;
            let mut raw = [0u8; 48];
            if read_data(tracee, &mut raw, peek_reg(tracee, RegVersion::Original, Reg::Sysarg2)) < 0
            {
                return 0;
            }
            let mut a = [0u64; 6];
            for (i, v) in a.iter_mut().enumerate() {
                *v = u64::from_ne_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
            }
            match call {
                SYS_BIND => {
                    if let Some(mut sa) = read_sockaddr(tracee, a[1]) {
                        mod_port(tracee, true, true, false, &mut sa, Some(&mut a));
                    }
                }
                SYS_CONNECT => {
                    if let Some(mut sa) = read_sockaddr(tracee, a[1]) {
                        if is_localhost(&sa) {
                            mod_port(tracee, true, false, false, &mut sa, Some(&mut a));
                        }
                    }
                }
                SYS_SENDTO => {
                    if a[4] != 0 {
                        if let Some(mut sa) = read_sockaddr(tracee, a[4]) {
                            if is_localhost(&sa) {
                                mod_port(tracee, true, false, true, &mut sa, Some(&mut a));
                            }
                        }
                    }
                }
                _ => {}
            }
            0
        }
        _ => 0,
    }
}

impl PortSwitch {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::SysEnterEnd { .. } => handle_sysenter_end(tracee),
            _ => 0,
        }
    }
    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        &FILTERED_SYSNUMS
    }
    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self::default()
    }
}

static FILTERED_SYSNUMS: &[(Sysnum, Word)] = &[
    (Sysnum::bind, FILTER_SYSEXIT),
    (Sysnum::connect, FILTER_SYSEXIT),
    (Sysnum::socketcall, FILTER_SYSEXIT),
    (Sysnum::sendto, FILTER_SYSEXIT),
    (Sysnum::recvfrom, FILTER_SYSEXIT),
];
