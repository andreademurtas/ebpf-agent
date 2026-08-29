# Build pipeline

## Compile time

```
cargo build (stable, host)
 └─ builds ebpf-agent-common and ebpf-agent
     └─ ebpf-agent's build.rs: aya_build::build_ebpf() spawns
        a second cargo invocation:
          rustup run nightly cargo build
            --target bpfel-unknown-none
            -Z build-std=core
            --release
        with bpf-linker as the linker and --btf for the BTF sections
     └─ the resulting eBPF ELF lands in OUT_DIR
 └─ main.rs embeds it with include_bytes_aligned!(OUT_DIR/ebpf-agent)
```

Two compilations with different toolchains and targets are needed. Cargo cannot express this natively (artifact dependencies are still unstable), so the build script orchestrates the second invocation. This is also why ebpf-agent-ebpf appears among the agent's build-dependencies: cargo rebuilds everything when the probe sources change.

The result is a single self-contained executable: the BPF ELF travels inside the agent binary.

## eBPF ELF layout

Relocatable `elf64-bpf` object. Relevant sections:

- `tracepoint`: the program, one symbol per function marked with the macro
- `license`: NUL-terminated string read by the kernel at load time
- `.BTF` and `.BTF.ext`: type info and relocation records for CO-RE

## Runtime

```
sudo ./ebpf-agent
 └─ aya parses the embedded ELF (programs, maps, license, BTF)
 └─ program.load()      bpf(BPF_PROG_LOAD) syscall
     └─ the verifier walks every path of the bytecode and proves
        it terminates and never touches out-of-bounds memory;
        on rejection the error carries the verifier log
     └─ on success the bytecode is JIT-compiled to native code
 └─ program.attach(category, name)
     └─ from here on, every occurrence of the event runs the
        program in kernel context
```

Detaching needs no explicit cleanup: programs and links are file descriptors, and when they are closed (drop of the `Ebpf` struct) the kernel unloads everything.

## Verifier constraints to keep in mind

- 512 byte BPF stack
- Code must be compiled optimized: without optimizations rustc
  generates useless spills and keeps `core` panic paths alive,
  which the verifier rejects. Hence the `opt-level = 3`,
  `panic = "abort"` and `lto = true` overrides in the dev profile
