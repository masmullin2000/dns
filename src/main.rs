use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

mod config;
mod server;

use config::Config;
use server::{tcp_server, udp_server};

#[cfg(any(target_env = "msvc", target_os = "freebsd"))]
use std::alloc::Syatem as Malloc;
#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use tikv_jemallocator::Jemalloc as Malloc;

#[global_allocator]
static GLOBAL: Malloc = Malloc;

#[derive(Parser)]
struct Args {
    #[clap(short, long, default_value = "/opt/dns/dns.toml")]
    config: std::path::PathBuf,
}

fn main() -> Result<()> {
    std::panic::set_hook(Box::new(|p| {
        eprintln!("panic: {p:?}");
        std::process::exit(1);
    }));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async { run().await })
}

async fn run() -> Result<()> {
    let args = Args::parse();
    let config: Config = std::fs::read_to_string(args.config)?.parse()?;
    let config = Arc::new(config);

    let config_clone = config.clone();
    tokio::spawn(async move {
        udp_server(config_clone).expect("udp_server failed");
    });
    Box::pin(tcp_server(config)).await
}
