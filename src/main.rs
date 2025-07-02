use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(any(target_env = "msvc", target_os = "freebsd"))]
use std::alloc::System as Malloc;
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
    // Initialize structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dns=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    std::panic::set_hook(Box::new(|p| {
        error!("DNS server panic: {p:?}");
        std::process::exit(1);
    }));

    let args = Args::parse();
    let config = args.config.as_str();
    info!("Starting DNS server with config: {config}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async { lib::run(config).await })
}
