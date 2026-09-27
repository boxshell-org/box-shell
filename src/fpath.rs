//! Fixed-capacity, NUL-terminated path buffer with `char[PATH_MAX]` semantics.
//!
//! The C implementation relies on fixed-size stack buffers everywhere; this
//! type reproduces that contract (bounded length, `ENAMETOOLONG` on overflow)
//! without copying cost and without UTF-8 assumptions — Linux paths are bytes.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::PATH_MAX;

#[derive(Clone)]
pub struct FixedPath {
    buf: [u8; PATH_MAX],
    len: usize,
}

impl FixedPath {
    pub fn new() -> Self {
        FixedPath { buf: [0; PATH_MAX], len: 0 }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut p = FixedPath::new();
        p.set(bytes);
        p
    }

    /// Replace the content; truncates at the first NUL byte, like strcpy().
    /// Silently truncates over-long input — callers that care use `try_set`.
    pub fn set(&mut self, bytes: &[u8]) {
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let len = nul.min(PATH_MAX - 1);
        self.buf[..len].copy_from_slice(&bytes[..len]);
        self.buf[len] = 0;
        self.len = len;
    }

    /// Fallible variant: `-ENAMETOOLONG` if the (NUL-truncated) input does not
    /// fit, including its terminator.
    pub fn try_set(&mut self, bytes: &[u8]) -> Result<(), i32> {
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if nul + 1 > PATH_MAX {
            return Err(-libc::ENAMETOOLONG);
        }
        self.buf[..nul].copy_from_slice(&bytes[..nul]);
        self.buf[nul] = 0;
        self.len = nul;
        Ok(())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mutable view of the *whole* buffer (capacity PATH_MAX) — for
    /// kernel writes like `read_string` that fill it in place.
    /// Afterwards call [`set_len`] or [`sync_len_from_nul`].
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf[..]
    }

    /// Set the logical length after writing through `as_mut_bytes`.
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.buf.len());
    }

    /// Recover the length of a NUL-terminated string written through
    /// `as_mut_bytes` (C callers rely on implicit `strlen`).
    pub fn sync_len_from_nul(&mut self) {
        let nul = self
            .buf
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.buf.len());
        self.len = nul;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Raw NUL-terminated view (as C string bytes).
    #[inline]
    pub fn as_c_bytes(&self) -> &[u8] {
        &self.buf[..self.len + 1]
    }

    /// `strlen` bound check used at the top of canonicalize().
    pub fn would_overflow(&self, extra: usize) -> bool {
        self.len + extra + 1 > PATH_MAX
    }

    /// Truncate to `new_len` (must be <= current len).
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            self.len = new_len;
            self.buf[new_len] = 0;
        }
    }

    /// Append a component, inserting a '/' separator when needed
    /// (join_paths() semantics for a single pair).
    pub fn push_component(&mut self, component: &[u8]) -> Result<(), i32> {
        let need_sep = self.len > 0
            && self.buf[self.len - 1] != b'/'
            && component.first() != Some(&b'/');
        let skip_first = self.len > 0
            && self.buf[self.len - 1] == b'/'
            && component.first() == Some(&b'/');
        let add = component.len() + usize::from(need_sep) - usize::from(skip_first);
        if self.len + add + 1 >= PATH_MAX {
            return Err(-libc::ENAMETOOLONG);
        }
        if need_sep {
            self.buf[self.len] = b'/';
            self.len += 1;
        }
        let src = if skip_first { &component[1..] } else { component };
        self.buf[self.len..self.len + src.len()].copy_from_slice(src);
        self.len += src.len();
        self.buf[self.len] = 0;
        Ok(())
    }

    /// Remove the last path component (`pop_component()` semantics).
    pub fn pop_component(&mut self) {
        if self.len <= 1 {
            return;
        }
        let mut off = self.len - 1;
        while off > 1 && self.buf[off] == b'/' {
            off -= 1;
        }
        while off > 1 && self.buf[off] != b'/' {
            off -= 1;
        }
        self.truncate(off);
    }

    /// Remove a trailing "/" or "/." (`chop_finality()`).
    pub fn chop_finality(&mut self) {
        if self.len == 0 {
            return;
        }
        let last = self.buf[self.len - 1];
        if last == b'.' {
            if self.len == 2 {
                self.truncate(1);
            } else {
                self.truncate(self.len - 2);
            }
        } else if last == b'/' && self.len > 1 {
            self.truncate(self.len - 1);
        }
    }

    /// Replace the first `old_prefix_len` bytes by `new_prefix`
    /// (`substitute_path_prefix()` semantics).
    pub fn substitute_prefix(&mut self, old_prefix_len: usize, new_prefix: &[u8]) -> Result<usize, i32> {
        let path_len = self.len;
        let mut new_len: usize;
        if new_prefix.len() == 1 {
            // "/foo" -> "/" ; "/foo/bin" -> "/bin".
            let tail = path_len - old_prefix_len;
            if tail != 0 {
                self.buf.copy_within(old_prefix_len..path_len, 0);
                new_len = tail;
            } else {
                self.buf[0] = b'/';
                new_len = 1;
            }
        } else if old_prefix_len == 1 {
            // "/" -> "/foo" ; "/bin" -> "/foo/bin".
            new_len = new_prefix.len() + path_len;
            if new_len >= PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            if path_len > 1 {
                self.buf.copy_within(0..path_len, new_prefix.len());
                self.buf[..new_prefix.len()].copy_from_slice(new_prefix);
            } else {
                self.buf[..new_prefix.len()].copy_from_slice(new_prefix);
                new_len = new_prefix.len();
            }
        } else {
            new_len = path_len - old_prefix_len + new_prefix.len();
            if new_len >= PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            self.buf.copy_within(old_prefix_len..path_len, new_prefix.len());
            self.buf[..new_prefix.len()].copy_from_slice(new_prefix);
        }
        self.len = new_len;
        self.buf[new_len] = 0;
        Ok(new_len)
    }
}

impl Default for FixedPath {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for FixedPath {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl DerefMut for FixedPath {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.buf[..len]
    }
}

impl fmt::Display for FixedPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.as_bytes()))
    }
}

impl fmt::Debug for FixedPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl AsRef<[u8]> for FixedPath {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
