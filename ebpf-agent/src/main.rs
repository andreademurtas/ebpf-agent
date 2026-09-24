use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use ebpf_agent_common::{ExecEvent, ExitEvent, ForkEvent, EVENT_EXEC, EVENT_EXIT, EVENT_FORK};
use log::{info, warn};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

fn c_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn read_event<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    Some(unsafe { (bytes.as_ptr() as *const T).read_unaligned() })
}

fn handle_event(bytes: &[u8]) {
    match read_event::<u32>(bytes) {
        Some(EVENT_EXEC) => {
            if let Some(event) = read_event::<ExecEvent>(bytes) {
                println!(
                    "execve pid={} uid={} comm={} filename={}",
                    event.pid,
                    event.uid,
                    c_str(&event.comm),
                    c_str(&event.filename),
                );
            }
        }
        Some(EVENT_FORK) => {
            if let Some(event) = read_event::<ForkEvent>(bytes) {
                println!("fork pid={} ppid={}", event.pid, event.ppid);
            }
        }
        Some(EVENT_EXIT) => {
            if let Some(event) = read_event::<ExitEvent>(bytes) {
                println!("exit pid={}", event.pid);
            }
        }
        _ => {}
    }
}

fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program: &str,
    category: &str,
    name: &str,
) -> anyhow::Result<()> {
    let tracepoint: &mut TracePoint = ebpf
        .program_mut(program)
        .with_context(|| format!("program {program} not found"))?
        .try_into()?;
    tracepoint
        .load()
        .with_context(|| format!("failed to load program {program}"))?;
    tracepoint
        .attach(category, name)
        .with_context(|| format!("failed to attach {program} to {category}:{name}"))?;
    info!("{program} attached to {category}:{name}");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        warn!("failed to raise RLIMIT_MEMLOCK, map creation may fail on kernels < 5.11");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-agent"
    )))
    .context("failed to load eBPF object")?;

    attach_tracepoint(&mut ebpf, "handle_execve", "syscalls", "sys_enter_execve")?;
    attach_tracepoint(&mut ebpf, "handle_fork", "task", "task_newtask")?;
    attach_tracepoint(&mut ebpf, "handle_exit", "sched", "sched_process_exit")?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("map EVENTS not found")?)?;
    let mut events = AsyncFd::with_interest(ring, Interest::READABLE)?;

    info!("press Ctrl-C to exit");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            guard = events.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    handle_event(&item);
                }
                guard.clear_ready();
            }
        }
    }

    info!("exiting");
    Ok(())
}
