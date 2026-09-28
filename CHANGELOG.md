# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to the version numbering of the PRoot release it
re-implements ([Termux PRoot 5.1.0](https://github.com/termux/proot)).

## [Unreleased]

### Added

- Complete open-source documentation system:
  - `README.md` with feature overview, quick start, and badges
  - mdBook documentation site under `docs/` (user guide, CLI reference,
    architecture, extensions, mixed-mode/QEMU, security model,
    development and testing guides)
  - `doc/proot.1` manual page
  - `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
    `CHANGELOG.md`
  - GitHub issue templates and pull-request template
  - `docs` CI workflow: `cargo doc` plus mdBook build and GitHub Pages
    deployment

### Changed

- Expanded crate-level and module-level rustdoc coverage.

## [5.1.0] — clean-room Rust rewrite of PRoot 5.1.0

### Added

- Full clean-room Rust port of Termux PRoot 5.1.0:
  - User-space `chroot` (`-r`, `-R`, `-S`)
  - Virtual bind mounts (`-b`, `-m`) with symlink-deref control
  - QEMU user-mode mixed execution (`-q`) with `/host-rootfs`
  - ABI-aware syscall translation (x86-64, x32, i386, arm, arm64, sh4
    tables in `data/`)
  - ELF parsing, interpreter (`PT_INTERP`) rewriting, loader stub, and
    shebang (`#!`) interpretation
  - Extensions: `-0`/`-i` fake identity, `--link2symlink`, `-H`
    hidden files, `-k` kernel-release kompat, `-p` port switch,
    `-L` symlink-size fix, `--sysvipc` (shm/sem/msg + helper daemon),
    mountinfo rewriting
  - Seccomp-accelerated syscall filtering
  - `--kill-on-exit`, `-w`, `-v` handling identical to C

- `src/sys.rs` FFI boundary: every libc/syscall call is a thin audited
  wrapper; the rest of the codebase contains no direct FFI.
- Freestanding `loader/` sub-crate (`no_std`, position-independent)
  injected into tracees for `execve` completion, matching the C
  loader's role.
- Modern Rust toolchain: edition 2024, MSRV 1.85, rustfmt/clippy
  enforcement, `unsafe_op_in_unsafe_fn` denied, cargo-deny policy,
  GitHub Actions CI, Dependabot.

### Fixed (relative to naive ports)

- `errno` is cleared on `process_vm_*` fast paths, matching the C
  convention — stale errno previously poisoned `getresuid`-style
  emulations and corrupted wait-status delivery.
- `SIGTRAP` delivery semantics: only the first SIGTRAP is consumed for
  ptrace option setup; subsequent ones reach the guest handler.
- `-q` runner resolution happens against the *host* filesystem (matching
  C's `reconf.tracee == NULL` path), so the QEMU binary is found via the
  host `PATH` rather than the guest rootfs.
- Kompat extension configuration is shared across tracees
  (`Rc<RefCell<…>>`), matching C's `INHERIT_PARENT → shared` model.
- Misaligned `&mut *bytes.cast::<libc::stat>()` uses replaced with typed
  reads — a genuine alignment-UB fix.
- No `static mut` anywhere: event flags are atomics, the pipe-shadow
  table is `thread_local!`, netlink probing uses an atomic cache.

### Validation

- Upstream C integration suite: **113 checks pass, 0 failures**
  (8 environment skips, 9 expected failures — identical to the C
  baseline; two QEMU-runner tests actually pass *better* than C because
  the Rust binary has no `libtalloc` dependency).
- `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
  `cargo test`, `cargo deny check`, debug + release builds all clean.

[Unreleased]: https://github.com/boxshell-org/box-shell/compare/v5.1.0...HEAD
[5.1.0]: https://github.com/boxshell-org/box-shell/releases/tag/v5.1.0
