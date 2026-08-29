# Toolchain

## Components

| Component | Role |
|---|---|
| Rust stable | builds the userspace agent |
| Rust nightly + `rust-src` | builds the probe for the `bpfel-unknown-none` target |
| bpf-linker | links LLVM bitcode and produces the final eBPF ELF |
| System LLVM | libraries bpf-linker is compiled against |

## Why nightly only for the probe

The `bpfel-unknown-none` target is tier 3: rustup does not ship a precompiled `core` for it. It has to be rebuilt from source with `-Z build-std=core`, which is nightly only. The `rust-src` component provides the sources of `core`.

## The LLVM version chain

rustc emits LLVM bitcode, bpf-linker consumes it. Bitcode is not backward compatible: an older LLVM cannot read bitcode produced by a newer one. Rule of thumb:

```
bpf-linker LLVM >= rustc nightly LLVM
```

To check both versions:

```sh
rustup run nightly rustc -vV | grep LLVM
```

The LLVM version of bpf-linker is chosen at `cargo install` time through a feature flag (`llvm-23` is the default in 0.11).

If the build starts failing with `failure linking module` after a nightly update, the nightly almost certainly moved to a new LLVM major: update the system LLVM and rebuild bpf-linker.

## Setup used

```sh
rustup toolchain install nightly --component rust-src
# apt.llvm.org repo, branch llvm-toolchain-noble-23
sudo apt-get install llvm-23-dev
LLVM_PREFIX=/usr/lib/llvm-23 cargo install bpf-linker
```

`LLVM_PREFIX` lets the bpf-linker build script find `llvm-config` when the binary in PATH carries a version suffix (`llvm-config-23`).

## Runtime requirements

- Kernel >= 5.8 for the ring buffer (`BPF_MAP_TYPE_RINGBUF`)
- BTF exposed at `/sys/kernel/btf/vmlinux` (`CONFIG_DEBUG_INFO_BTF=y`), required for CO-RE
- Privileges: root, or `CAP_BPF` + `CAP_PERFMON` (kernel >= 5.8)

For the secondary target, kernel 5.10: ring buffer and capabilities are available, the critical point is BTF, often missing in custom embedded builds. Options: ship an external BTF file (BTFHub) or stick to tracepoints with a stable layout, reducing the need for CO-RE.
