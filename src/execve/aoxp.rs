//! Arrays of pointers in the tracee's memory (argv[], envp[]) —
//! port of execve/aoxp.c.
//!
//! Each entry caches a local copy on first access; `push_array_of_xpointers`
//! writes back the pointer table plus every modified pointee into a fresh
//! tracer-allocated block.

use crate::tracee::mem::{alloc_mem, peek_word, read_string, writev_data};
use crate::tracee::reg::{is_32on64_mode, peek_reg, poke_reg, sizeof_word, Reg, RegVersion};
use crate::tracee::Tracee;
use crate::Word;

/// `ARG_MAX`.
const ARG_MAX: usize = 131072;

/// One pointer slot: `remote` is the tracee-side address, `local` the
/// cached/rewritten payload (string including NUL) once read or replaced.
#[derive(Clone)]
pub struct XPointer {
    pub remote: Word,
    pub local: Option<Vec<u8>>,
}

/// `ArrayOfXPointers`.
#[derive(Default)]
pub struct XPointerArray {
    pub entries: Vec<XPointer>,
}

/// `fetch_array_of_xpointers()` — copy the NULL-terminated pointer array
/// stored in tracee memory at `reg`'s value (or exactly `nb_entries` when
/// nonzero).
pub fn fetch_array_of_xpointers(
    tracee: &Tracee,
    reg: Reg,
    nb_entries: usize,
) -> Result<XPointerArray, i32> {
    let address = peek_reg(tracee, RegVersion::Current, reg);
    let w = sizeof_word(tracee) as Word;
    let mut array = XPointerArray::default();

    let mut i = 0usize;
    loop {
        if nb_entries != 0 && i >= nb_entries {
            break;
        }
        clear_errno();
        let pointer = peek_word(tracee, address + i as Word * w);
        let e = crate::path::errno();
        if e != 0 {
            return Err(-e);
        }
        // The C loop pushes the NULL terminator before stopping.
        array.entries.push(XPointer {
            remote: pointer,
            local: None,
        });
        i += 1;
        if nb_entries == 0 && pointer == 0 {
            break;
        }
    }
    Ok(array)
}

/// `read_xpointee_as_string()` — fetch+cache entry @index as a
/// NUL-terminated string.  Returns `Ok(None)` for a NULL remote.
pub fn read_xpointee_as_string(
    tracee: &Tracee,
    array: &mut XPointerArray,
    index: usize,
) -> Result<Option<Vec<u8>>, i32> {
    debug_assert!(index < array.entries.len());
    if let Some(local) = &array.entries[index].local {
        return Ok(Some(local.clone()));
    }
    if array.entries[index].remote == 0 {
        return Ok(None);
    }
    let mut tmp = vec![0u8; ARG_MAX];
    let status = read_string(tracee, &mut tmp, array.entries[index].remote);
    if status < 0 {
        return Err(status);
    }
    if status as usize >= ARG_MAX {
        return Err(-libc::ENOMEM);
    }
    let s = tmp[..status as usize].to_vec();
    array.entries[index].local = Some(s.clone());
    Ok(Some(s))
}

/// `sizeof_xpointee_as_string()` — byte length including NUL.
pub fn sizeof_xpointee_as_string(
    tracee: &Tracee,
    array: &mut XPointerArray,
    index: usize,
) -> Result<usize, i32> {
    match read_xpointee_as_string(tracee, array, index)? {
        Some(s) => Ok(s.len()),
        None => Ok(0),
    }
}

/// `is_env_name()` — "NAME=" prefix match (`variable` is NUL-terminated).
pub fn is_env_name(variable: &[u8], name: &str) -> bool {
    let name = name.as_bytes();
    let len = name.len();
    variable.first() == name.first()
        && variable.len() > len
        && variable[len] == b'='
        && &variable[..len] == name
}

/// `compare_xpointee_env()` from ldso.c: does entry @index's string start
/// with `reference` followed by '='?
pub fn compare_xpointee_env(
    tracee: &Tracee,
    array: &mut XPointerArray,
    index: usize,
    reference: &str,
) -> Result<i32, i32> {
    match read_xpointee_as_string(tracee, array, index)? {
        None => Ok(0),
        Some(v) => Ok(is_env_name(&v, reference) as i32),
    }
}

/// `find_xpointee()` over env entries; returns the index of the first
/// match or `entries.len()`.
pub fn find_xpointee_env(
    tracee: &Tracee,
    array: &mut XPointerArray,
    reference: &str,
) -> Result<usize, i32> {
    for i in 0..array.entries.len() {
        if compare_xpointee_env(tracee, array, i, reference)? != 0 {
            return Ok(i);
        }
    }
    Ok(array.entries.len())
}

/// `write_xpointee_as_string()` — mark entry @index as replaced by a
/// local copy of @string (materialized into the tracee on push).
pub fn write_xpointee_string(array: &mut XPointerArray, index: usize, string: &[u8]) {
    debug_assert!(index < array.entries.len());
    let mut v = string.to_vec();
    if !v.ends_with(b"\0") {
        v.push(0);
    }
    array.entries[index].local = Some(v);
}

/// `write_xpointees()` — variadic sugar.
pub fn write_xpointees(array: &mut XPointerArray, index: usize, strings: &[&[u8]]) {
    for (i, s) in strings.iter().enumerate() {
        write_xpointee_string(array, index + i, s);
    }
}

/// `resize_array_of_xpointers()` — insert (`delta` > 0) or remove
/// (`delta` < 0) slots at `index`.
pub fn resize_array_of_xpointers(array: &mut XPointerArray, index: usize, delta: isize) -> i32 {
    debug_assert!(index <= array.entries.len());
    if delta > 0 {
        for _ in 0..delta {
            array.entries.insert(
                index,
                XPointer {
                    remote: 0,
                    local: None,
                },
            );
        }
    } else if delta < 0 {
        let n = (-delta) as usize;
        debug_assert!(index + n <= array.entries.len());
        array.entries.drain(index..index + n);
    }
    0
}

/// `push_array_of_xpointers()` — write the pointer table + modified
/// pointees to a fresh tracer-allocated block and update `reg`.
pub fn push_array_of_xpointers(
    tracee: &mut Tracee,
    array: &mut XPointerArray,
    reg: Reg,
) -> i32 {
    let w = sizeof_word(tracee);
    let n = array.entries.len();

    // Sizes: pointer table first, then each modified pointee.
    let mut total_size = n * w;
    for i in 0..n {
        if array.entries[i].local.is_some() {
            match sizeof_xpointee_as_string(tracee, array, i) {
                Ok(s) => total_size += s,
                Err(e) => return e,
            }
        }
    }
    if array.entries.iter().all(|e| e.local.is_none()) {
        return 0;
    }

    let base = alloc_mem(tracee, total_size as i64);
    if base == 0 {
        return -libc::E2BIG;
    }

    let mut pod = vec![0u8; n * w];
    let mut blob = Vec::with_capacity(total_size - n * w);
    let mut off = n * w;
    for i in 0..n {
        if let Some(local) = array.entries[i].local.take() {
            array.entries[i].remote = base + off as Word;
            off += local.len();
            blob.extend_from_slice(&local);
            array.entries[i].local = Some(local);
        }
        let r = array.entries[i].remote;
        if is_32on64_mode(tracee) {
            pod[i * 4..i * 4 + 4].copy_from_slice(&(r as u32).to_ne_bytes());
        } else {
            pod[i * 8..i * 8 + 8].copy_from_slice(&r.to_ne_bytes());
        }
    }
    let st = writev_data(tracee, base, &[&pod, &blob]);
    if st < 0 {
        return st;
    }
    poke_reg(tracee, reg, base);
    0
}

/// Clear thread-local errno before a `peek_word` (mirrors `errno = 0` in C).
fn clear_errno() {
    unsafe {
        *libc::__errno_location() = 0;
    }
}
