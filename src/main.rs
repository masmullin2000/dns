use std::sync::Arc;

use anyhow::Result;

mod config;
mod server;

use config::Config;
use server::{tcp_server, udp_server};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

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
    let mut config: Config = "/opt/dns/dns.toml".parse()?;
    config.build_blocklist();
    let config = Arc::new(config);

    tokio::spawn(async move {
        udp_server(config).expect("udp_server failed");
    });
    Box::pin(tcp_server()).await
}