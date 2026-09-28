# Installation

## From source (the only supported method today)

box-shell is a single-crate Rust workspace with one dependency
(`libc`). There is nothing to configure and no system libraries to
install beyond Rust itself.

```console
$ git clone https://github.com/boxshell-org/box-shell.git
$ cd box-shell
$ cargo build --release
$ ./target/release/proot --version
box-shell 5.1.0
```

Requirements:

- **Linux.** box-shell instruments `ptrace(2)`, `seccomp`,
  `process_vm_readv/writev`, and `/proc/<pid>/fd`. It does not run on
  macOS or Windows; Android works the same way it does for the C
  implementation (through Termux).
- **Rust 1.85 or newer.** `rust-toolchain.toml` pins `stable` and pulls
  in `rustfmt` + `clippy` automatically. Edition 2024 is in use.
- Kernel: any reasonably modern Linux. `process_vm_*` (≥ 3.2) is
  preferred for tracee memory access; the `PTRACE_PEEK/POKE` fallback
  covers older kernels. Seccomp acceleration needs `seccomp` filtering
  support (≥ 3.5 realistically, with `SECCOMP_MODE_FILTER`).

## Installing the binary

```console
$ cargo install --path .          # installs `proot` into ~/.cargo/bin
# or
$ install -Dm755 target/release/proot ~/.local/bin/proot
```

The binary is deliberately named `proot` — it is a drop-in replacement
for the C implementation. If you already have C `proot` installed, pick
a different destination or rename (e.g. `proot-rs`).

## Installing the manual page

```console
$ install -Dm644 doc/proot.1 ~/.local/share/man/man1/proot.1
$ man proot
```

## Verifying the install

```console
$ proot -0 /usr/bin/id -u
0
$ proot -b /etc/hostname /bin/cat /etc/hostname
<your hostname>
$ proot -v 1 /bin/true          # verbose banner, one line
```

## Cross-compiling / Android

For Android/Termux use the same build inside the Termux Rust package;
all Termux-specific options (`-0`, `-l`, `--sysvipc`, `-p`, `-L`,
`-H`, `--kill-on-exit`) are implemented except `--ashmem-memfd`, which
is Android-Bionic-specific and not yet ported — see
[Compatibility](compatibility.md).
