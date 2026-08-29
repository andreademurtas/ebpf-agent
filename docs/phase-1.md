# Phase 1: execve events over the ring buffer

Goal: the probe reads real data (pid, uid, comm, filename) from `sys_enter_execve` and ships it to userspace through a ring buffer. The agent prints one line per execve on the machine.

## Hook choice

Three candidates for observing execve, with different trade-offs:

- `syscalls:sys_enter_execve` (chosen): stable ABI, the field layout is exported in `/sys/kernel/tracing/events/syscalls/sys_enter_execve/format` and does not change across kernel versions. No kernel struct access, so no CO-RE needed. Downsides: it fires on the attempt (the exec may still fail), it misses `execveat`, and arguments live in user memory.
- kprobe on the syscall handler: works on any kernel function, but the symbol name is architecture dependent, the ABI is not stable, and reading arguments requires walking `pt_regs`. More fragile across kernels, unnecessary here.
- `sched_process_exec` tracepoint: fires once the exec has succeeded, covers both execve and execveat. Better signal, but the interesting data comes as offsets into the trace record and the pre-exec image is already gone. A candidate for a later phase.

At `sys_enter_execve` the process has not been replaced yet, so `comm` still holds the name of the calling program, and `filename` holds what is about to be executed. The pair "who calls exec on what" is exactly the signal needed later for rules like "web server spawns a shell".

## Event struct

`ExecEvent` in ebpf-agent-common, `#[repr(C)]`, fixed-size arrays for strings (`comm` 16 bytes, kernel limit, and `filename` 256 bytes, truncating longer paths). Fixed sizes because BPF cannot allocate: the event size must be known at compile time to reserve ring buffer space.

## Probe flow

1. `EVENTS.reserve::<ExecEvent>(0)`: reserves space directly in the ring buffer. The event is written in place, never on the BPF stack: the struct is 280 bytes and the stack is 512, building it there and copying would waste more than half of it.
2. `bpf_get_current_pid_tgid() >> 32`: the upper half is the tgid, which is what userspace calls pid. The lower half is the thread id.
3. `bpf_get_current_uid_gid()` lower half: the real uid.
4. `bpf_get_current_comm()`: the 16-byte comm of the current task.
5. `ctx.read_at(16)`: the userspace pointer to the filename string, at the offset published in the tracepoint format file.
6. `bpf_probe_read_user_str_bytes`: copies the NUL-terminated string from user memory into the reserved event. It can fail (the page may be swapped out or the pointer bogus), hence the fallible path.
7. `submit` on success, `discard` on failure.

## Verifier notes

- A ring buffer reservation is a tracked resource: every code path must end in `submit` or `discard`. Leaking the reservation on any path makes the verifier reject the program with an unreleased reference error.
- `bpf_probe_read_user_str_bytes` gets a destination slice with compile-time size, which gives the verifier the bounds proof it needs for the helper call.
- Reading user memory can fail at any time: helpers return errors instead of faulting, and the program must handle them.

## Userspace flow

The `RingBuf` map is wrapped in tokio's `AsyncFd`: the ring buffer fd becomes readable when the kernel side commits events, so the agent sleeps in epoll instead of polling. On wakeup it drains the ring (`next()` until empty), reinterprets each item as an `ExecEvent` with an unaligned read, and prints it. Strings are cut at the first NUL.

## Verification

```sh
cargo build
sudo ./target/debug/ebpf-agent
```

From another shell run `ls` or any command: one `execve` line per process appears, with `comm` showing the parent shell and `filename` the executed binary.

## Known limits, intentional for now

- `execveat` is not hooked (rare on real systems, will be considered later).
- The event reports the exec attempt, not its success.
- Arguments (`argv`) are not captured.
- Paths longer than 255 bytes are truncated.
