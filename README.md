# Reproduction & fix — goya-template issue #35

Reproduces and fixes:

```
load program: invalid argument: Global function memcpy() doesn't return scalar.
Only those are supported.
```

(Exact wording depends on which global helper is hit first: `memcpy`, `memmove`
or `memset`. All come from the same root cause.)

## Root cause

* `bpf_probe_read_user_str_bytes` / `bpf_probe_read_kernel_str_bytes` return a
  `&[u8]` (pointer + **runtime** length).
* Aya (`aya-ebpf/src/lib.rs`) ships **global** fallback functions
  `memcpy`/`memmove`/`memset` that return `void`
  (`#[no_mangle] extern "C" fn ...`).
* As soon as the program **copies** the runtime-length string (e.g. into a map
  value with `copy_from_slice`), LLVM emits a `call memcpy(dst, src,
  runtime_len)`.
* Since **kernel 5.18** (function-by-function verification), every global
  function that is called must return a **scalar**. `memcpy` & co return
  `void` -> the **kernel BPF verifier** rejects the program.

The message comes from the **kernel verifier**, not from cilium/ebpf or Goya
(Go). cilium/ebpf only surfaces the `BPF_PROG_LOAD` error
(`prog.go: "load program: %w"`), and Goya's generated loader only prints it.

## Layout

| Path            | What it is                                                                    |
|-----------------|-------------------------------------------------------------------------------|
| `eBPF-broken/`  | Aya program using `bpf_probe_read_user_str_bytes` + `copy_from_slice` of the **runtime length** result. **Fails** to load. |
| `eBPF-fixed/`   | Same intent using `bpf_probe_read_user_buf` (scalar `Result<(), i32>`) into a **fixed-size** buffer, no runtime-length copy. **Loads OK.** |
| `loader/`       | Rust crate that runs `aya-build` (like the goya-template host crate) and copies the ELFs into `loader-go/.ebpf/`. |
| `loader-go/`    | Minimal Go loader (cilium/ebpf, same call pattern as Goya's generated `{{project-name}}-go/main.go`). |

Both eBPF programs are uprobes (no specific target needed to *load* them) and
emit the same `license` section as the goya-template (`Dual MIT/GPL`), so the
only difference between the two is the string-reading pattern.

## Prerequisites

* Linux >= 5.18, root, `/sys/kernel/btf/vmlinux` present.
* Rust stable + `nightly` with the `rust-src` component (Aya builds with `-Z build-std=core`).
* `bpf-linker` on `$PATH`.
* Go + `cilium/ebpf`.

## Run

```sh
# 1. Build both eBPF programs (ELFs end up in loader-go/.ebpf/)
cargo run --release

# 2. Load them
cd loader-go
go build -o loader .
sudo ./loader .ebpf/test-broken   # -> LOAD ERROR (verifier rejects)
sudo ./loader .ebpf/test-fixed    # -> OK: collection loaded
```

## The fix (for Goya/Aya eBPF programs)

Do **not** read a variable-length string and then copy it. Use a helper that
returns a **scalar** into a **fixed-size** buffer, and never perform a
runtime-length `memcpy`/`copy_from_slice` in eBPF space:

```rust
use aya_ebpf::{
    helpers::bpf_probe_read_user_buf,
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

#[map]
pub static BUF: Array<[u8; 16]> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn enter(ctx: ProbeContext) {
    let ptr = match ctx.arg::<*const u8>(0) {
        Some(p) => p,
        None => return,
    };
    let mptr = match BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let v = unsafe { &mut *mptr };
    // scalar Result<(), i32>, fixed-size destination, no runtime-length copy
    if unsafe { bpf_probe_read_user_buf(ptr, v) }.is_ok() {
        // use v here
    }
}
```

Rules of thumb:

- Avoid `bpf_probe_read_user_str_bytes` / `bpf_probe_read_kernel_str_bytes`
  followed by any variable-length copy.
- Avoid any `memcpy`/`memmove`/`copy_from_slice` with a **runtime** length in
  eBPF space.
- Prefer `bpf_probe_read_user` / `bpf_probe_read_kernel` / the `*_buf`
  variants with a fixed buffer; use `bpf_strncmp` to compare strings.

## Results (observed)

Environment: Linux 6.12 x86_64, root, Rust nightly + rust-src, bpf-linker
0.11.1, Go 1.26, cilium/ebpf v0.20.0.

```
=== BROKEN (bpf_probe_read_user_str_bytes + copy_from_slice) ===
LOAD ERROR: program enter: load program: invalid argument:
Caller passes invalid args into func#2 ('memset') (14 line(s) omitted)

=== FIXED (bpf_probe_read_user_buf, fixed buffer) ===
OK: loaded program "enter"
OK: collection loaded
```

Bytecode evidence (objdump of the broken program): the `enter` program
contains a `call` into the global symbol `memcpy` with a runtime length
register; the symbol table lists `memcpy`/`memmove`/`memset` as
`FUNC GLOBAL HIDDEN` (void-returning) global functions.
