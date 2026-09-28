//! Diagnostic output, mirroring cli/note.c.
//!
//! `note()` prints `proot <severity>: <message>` on stderr; `SYSTEM` origin
//! appends the current errno's description.  `verbose!` is the per-tracee
//! gated form.

use std::sync::atomic::{AtomicI32, Ordering};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    System,
    Internal,
    User,
}

pub static GLOBAL_VERBOSE_LEVEL: AtomicI32 = AtomicI32::new(0);
static TOOL_NAME: std::sync::RwLock<&'static str> = std::sync::RwLock::new("proot");

pub fn set_tool_name(name: &'static str) {
    *TOOL_NAME.write().unwrap() = name;
}

pub fn tool_name() -> &'static str {
    TOOL_NAME.read().map(|g| *g).unwrap_or("proot")
}

pub fn global_verbose() -> i32 {
    GLOBAL_VERBOSE_LEVEL.load(Ordering::Relaxed)
}

/// Print a notice on stderr.  `tracee_verbose` is `Option<i32>`: when Some,
/// `-1` or lower suppresses INFO messages entirely (the C version checks
/// `tracee->verbose` inside `note()` when severity is INFO?  — actually it
/// doesn't; VERBOSE() gates at the call site.  We keep the same split.)
pub fn note(severity: Severity, origin: Origin, args: std::fmt::Arguments) {
    if severity == Severity::Info && global_verbose() < 0 {
        return;
    }
    let tool = tool_name();
    match severity {
        Severity::Warning => eprint!("{} warning: ", tool),
        Severity::Error => eprint!("{} error: ", tool),
        Severity::Info => eprint!("{} info: ", tool),
    }
    eprint!("{}", args);
    match origin {
        Origin::System => {
            eprintln!(": {}", crate::strerror(crate::path::errno()));
        }
        _ => eprintln!(),
    }
}

/// `note(tracee, severity, origin, ...)` — verbose level comes from the
/// tracee when present, otherwise from the global level.
#[macro_export]
macro_rules! note {
    // The tracee-prefixed form is matched on the literal `Some(...)` token —
    // otherwise the two forms are ambiguous at the syntax level.
    (Some($tracee:expr_2021), $severity:expr_2021, $origin:expr_2021, $($arg:tt)*) => {{
        let _ = $tracee;
        $crate::note::note($severity, $origin, format_args!($($arg)*))
    }};
    (None, $severity:expr_2021, $origin:expr_2021, $($arg:tt)*) => {{
        $crate::note::note($severity, $origin, format_args!($($arg)*))
    }};
    ($severity:expr_2021, $origin:expr_2021, $($arg:tt)*) => {{
        $crate::note::note($severity, $origin, format_args!($($arg)*))
    }};
}

/// VERBOSE(tracee, level, ...) — emit an INFO message when the tracee's (or
/// the global) verbose level reaches `level`.
#[macro_export]
macro_rules! verbose {
    ($tracee:expr_2021, $level:expr_2021, $($arg:tt)*) => {{
        let v = $crate::tracee::verbose_of($tracee);
        if v >= $level {
            $crate::note::note($crate::note::Severity::Info,
                               $crate::note::Origin::Internal,
                               format_args!($($arg)*));
        }
    }};
}
