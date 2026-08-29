# Phase 0: scaffolding

Goal: a workspace that builds and a minimal probe that the kernel accepts, proving the whole pipeline works end to end.

## Workspace layout

```
ebpf-agent/
├── Cargo.toml            workspace root, shared dependency versions
├── ebpf-agent-common/    structs shared between probe and agent
├── ebpf-agent-ebpf/      the probes, compiled to BPF bytecode
└── ebpf-agent/           userspace agent, loads probes and reads events
```

Three crates because there are two very different execution environments:

- `ebpf-agent-ebpf` is `no_std`/`no_main` and targets `bpfel-unknown-none`. No standard library: inside the kernel there is no heap, no threads, no OS underneath.
- `ebpf-agent` is a normal host binary using aya to load the ELF, attach programs and read maps.
- `ebpf-agent-common` will hold the event structs. Events cross the ring buffer as raw bytes: the kernel side writes a struct, the user side reinterprets it. A single `#[repr(C)]` definition compiled by both sides makes layout mismatches impossible.

## Notable choices

- `default-members` in the workspace excludes the ebpf crate: it only makes sense for the BPF target and is built by aya-build, not by the host cargo invocation.
- Profile overrides (`opt-level = 3`, `panic = "abort"`, `lto = true`) apply to dev builds too: unoptimized BPF code gets rejected by the verifier.
- The ebpf crate has an empty `src/lib.rs`: it gives the crate a lib target so the agent can list it as a build-dependency (cargo only builds the lib of build-dependencies, never the bin).

## The probe

`handle_execve` is a tracepoint program attached to `syscalls:sys_enter_execve`. In this phase it does nothing (`r0 = 0; exit`, two instructions): its only purpose is validating compile, load, verifier and attach.

Details worth remembering:

- The `#[tracepoint]` macro places the function in the `tracepoint` ELF section, exported under its own name, which is the name the agent looks up.
- A `#[panic_handler]` is required to link any `no_std` binary, but in BPF it is dead code: the verifier rejects any path that could panic.
- The `license` ELF section is mandatory for many kernel helpers, same spirit as `EXPORT_SYMBOL_GPL` for modules.

## The agent

Steps in `main`:

1. Raise `RLIMIT_MEMLOCK`: on kernels < 5.11 BPF map memory is charged against it. No-op on newer kernels, kept for the 5.10 target.
2. `Ebpf::load(include_bytes_aligned!(...))`: parse the ELF embedded at compile time.
3. `program_mut("handle_execve")` + `load()`: the verifier runs here.
4. `attach("syscalls", "sys_enter_execve")`: from this moment every execve on the machine runs the probe.
5. Wait for Ctrl-C. Cleanup is implicit: dropping the `Ebpf` struct closes the file descriptors and the kernel detaches and unloads everything.

## Verification

```sh
cargo build
sudo ./target/debug/ebpf-agent
```

Expected output: a log line confirming the attach, then the process waits. `sudo bpftool prog list` from another shell shows the loaded program.
