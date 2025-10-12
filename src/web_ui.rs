#![allow(clippy::cognitive_complexity)]

use clap::Parser;
use tracing::Level;
// use tracing::{Level, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
struct Args {
    /// Location of the DNS configuration file
    #[clap(short, long, default_value = "/opt/dns/dns.toml")]
    config: String,

    /// Path to the DNS directory
    #[clap(short, long, default_value = "/opt/dns/")]
    directory: String,

    /// Port to listen on
    #[clap(short, long, default_value = "3000")]
    port: u16,

    /// Logging level (e.g., debug, info, warn, error, trace)
    #[clap(short, long, default_value = "info")]
    log_level: String,
}

fn parse_log_level(level: &str) -> Level {
    #[allow(clippy::match_same_arms)]
    match level.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

fn main() -> anyhow::Result<()> {
    let Args {
        config,
        directory,
        port,
        log_level,
    } = Args::parse();
    let log_level = parse_log_level(&log_level);

    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    let (tx, _rx) = tokio::sync::mpsc::channel(1);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    rt.block_on(async { lib::run_web(config, directory, port, tx).await })?;

    Ok(())
}
