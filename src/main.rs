use anyhow::Result;
use clap::Parser;

#[cfg(any(target_env = "msvc", target_os = "freebsd"))]
use std::alloc::Syatem as Malloc;
#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use tikv_jemallocator::Jemalloc as Malloc;

#[global_allocator]
static GLOBAL: Malloc = Malloc;

#[derive(Parser)]
struct Args {
    #[clap(short, long, default_value = "/opt/dns/dns.toml")]
    config: String,
}

fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|p| {
        eprintln!("panic: {p:?}");
        std::process::exit(1);
    }));
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async { lib::run(&args.config).await })
}
