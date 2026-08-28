use aya_build::{Package, Toolchain, build_ebpf};

fn main() -> anyhow::Result<()> {
    build_ebpf(
        [Package {
            name: "ebpf-agent-ebpf",
            root_dir: "../ebpf-agent-ebpf",
            ..Default::default()
        }],
        Toolchain::default(),
    )
}
