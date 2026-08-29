use anyhow::Context as _;
use aya::maps::RingBuf;
use aya::programs::TracePoint;
use ebpf_agent_common::ExecEvent;
use log::{info, warn};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

fn c_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
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

    let program: &mut TracePoint = ebpf
        .program_mut("handle_execve")
        .context("program handle_execve not found")?
        .try_into()?;
    program.load().context("failed to load program")?;
    program
        .attach("syscalls", "sys_enter_execve")
        .context("failed to attach tracepoint")?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("map EVENTS not found")?)?;
    let mut events = AsyncFd::with_interest(ring, Interest::READABLE)?;

    info!("probe attached to syscalls:sys_enter_execve, press Ctrl-C to exit");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            guard = events.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    if item.len() < size_of::<ExecEvent>() {
                        continue;
                    }
                    let event = unsafe { (item.as_ptr() as *const ExecEvent).read_unaligned() };
                    println!(
                        "execve pid={} uid={} comm={} filename={}",
                        event.pid,
                        event.uid,
                        c_str(&event.comm),
                        c_str(&event.filename),
                    );
                }
                guard.clear_ready();
            }
        }
    }

    info!("exiting");
    Ok(())
}
