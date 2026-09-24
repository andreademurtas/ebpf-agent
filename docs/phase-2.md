# Phase 2: process lineage

Goal: know, for every process, which process spawned it. Rules like "web server spawns a shell that runs a binary from /tmp" are statements about chains of processes, and a single execve event only shows one link.

The phase is split in two steps:

1. Kernel side: fork and exit events next to execve, over the same ring buffer.
2. Userspace side: a table of live processes built from those events, seeded from `/proc` at startup, used to print the ancestry of every execve.

Step 1 is done, step 2 is next.

## Hook choice for fork

- `sched:sched_process_fork`: the obvious candidate, rejected for two reasons. It fires for every new task, threads included, and the record gives no way to tell a thread from a process. Its layout also changed: on 5.10 the two comm fields are inline `char[16]` arrays and `child_pid` sits at offset 44, on the 6.18 kernel used here they became `__data_loc` dynamic strings and `child_pid` moved to offset 20. A probe with hardcoded offsets would silently read garbage on one of the two.
- `task:task_newtask` (chosen): fires in `copy_process` right after the new task gets its pid, and the record carries `clone_flags`. The probe drops anything with `CLONE_THREAD`, so only real processes are reported. Layout on both 5.10 and 6.18: `pid` at offset 8, `comm` at 12, `clone_flags` at 32.

Syscall tracepoints like `sys_enter_execve` are generated from the syscall prototype, so their layout is as stable as the syscall itself. Other tracepoints are ordinary kernel code: their format is stable by convention only and can change between releases, as `sched_process_fork` shows. All offsets in the probes assume a 64-bit kernel.

Offsets can be read without root from the kernel BTF, which describes the record of every tracepoint as a `trace_event_raw_<name>` struct:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep -A8 'struct trace_event_raw_task_newtask {'
```

With root, the same information is in `/sys/kernel/tracing/events/task/task_newtask/format`.

## What ppid means here

Inside `copy_process` the current task is still the parent, so `bpf_get_current_pid_tgid() >> 32` gives the tgid of the process that called fork or clone. That is the value reported as `ppid`. It differs from what `getppid()` returns in two cases:

- `CLONE_PARENT`: the kernel makes the child a sibling of the caller, so its real parent is the caller's parent.
- Reparenting: when a parent dies its children move to init or to the nearest subreaper, and `getppid()` changes. The fork event keeps the original parent.

For attack chains the original spawner is the useful information, so both differences are acceptable.

## Hook choice for exit

`sched:sched_process_exit` fires in `do_exit` for every exiting thread. The probe reads nothing from the record: it compares the thread id and the tgid returned by `bpf_get_current_pid_tgid` and reports only the exit of the thread group leader, whose tid equals the tgid.

Known limit: if the leader exits first (`pthread_exit` from `main`) while other threads keep running, the process is reported gone too early. Recent kernels add a `group_dead` field to the record that is exact, but it does not exist on 5.10.

## Event protocol

Three `#[repr(C)]` structs in ebpf-agent-common, each starting with a `kind: u32` field:

| Kind | Struct | Fields |
|---|---|---|
| 1 | `ExecEvent` | pid, uid, comm, filename |
| 2 | `ForkEvent` | pid, ppid |
| 3 | `ExitEvent` | pid |

Userspace reads the first four bytes of each ring buffer item, then reinterprets the item as the matching struct. The structs only contain `u32` fields and byte arrays, so there is no padding: every byte sent to userspace has been written by the probe, no stale stack contents end up in the event.

All three probes share one ring buffer on purpose. The BPF ring buffer is a single queue for all CPUs, and reservation order is the order userspace sees. The fork event of a child is emitted by the parent before the child is ever scheduled, so it always comes before the child's execve and exit. With per-CPU perf buffers, events produced on different CPUs would need to be sorted by timestamp in userspace.

## Probe flow

The fork and exit events are 12 and 8 bytes: they are built on the BPF stack and copied with `bpf_ringbuf_output`. The copy costs nothing at this size, and it avoids the reserve/submit pairing. The execve event keeps `reserve` because at 284 bytes it would take more than half of the 512 byte stack.

## Verification

```sh
cargo build
sudo ./target/debug/ebpf-agent
```

From another shell:

```sh
sh -c 'sleep 1; true'
```

Expected sequence, pids will differ:

```
fork pid=2001 ppid=1500
execve pid=2001 uid=1000 comm=bash filename=/usr/bin/sh
fork pid=2002 ppid=2001
execve pid=2002 uid=1000 comm=sh filename=/usr/bin/sleep
exit pid=2002
exit pid=2001
```

`true` is a shell builtin, so it produces no fork. A multithreaded program (a browser, `python3` with threads) produces one fork line per process and none per thread.
