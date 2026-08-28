# ebpf-agent

Minimal runtime security agent for Linux, written in Rust with [Aya](https://aya-rs.dev). It loads eBPF probes on process and network events to detect a simple attack chain: a compromised service spawns a shell, drops a binary in /tmp and opens a connection to an unknown host.

Work in progress.

## Requirements

- Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux`)
- Rust stable + nightly with `rust-src`
- `bpf-linker` built against an LLVM version at least as new as the one used by the nightly toolchain

## Build

```sh
cargo build
```

## Run

```sh
sudo ./target/debug/ebpf-agent
```
