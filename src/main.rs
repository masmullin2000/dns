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
    /// Location of the DNS configuration file
    #[clap(short, long, default_value = "/opt/dns/dns.toml")]
    config: String,
    /// Logging level for the DNS server (e.g., debug, info, warn, error, trace)
    #[clap(short, long, default_value = "info")]
    log_level: String,
}

fn parse_log_level(level: &str) -> tracing::Level {
    #[allow(clippy::match_same_arms)]
    match level.to_lowercase().as_str() {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO, // Default to INFO if unrecognized
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Initialize structured logging
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(parse_log_level(&args.log_level).into())
        .from_env_lossy();

    let layer = tracing_journald::layer().expect("Failed to create journald tracing");

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(env_filter)
        .with(layer)
        .init();

    std::panic::set_hook(Box::new(|p| {
        error!("DNS server panic: {p:?}");
        std::process::exit(1);
    }));

    let config = args.config.as_str();
    info!("Starting DNS server with config: {config}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async { lib::run(config).await })
}
