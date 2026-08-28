use anyhow::Context as _;
use aya::programs::TracePoint;
use log::{info, warn};

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

    info!("probe attached to syscalls:sys_enter_execve, press Ctrl-C to exit");
    tokio::signal::ctrl_c().await?;
    info!("exiting");
    Ok(())
}
