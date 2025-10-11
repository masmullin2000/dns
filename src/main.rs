#![allow(clippy::cognitive_complexity)]

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
struct Args {
    /// Location of the DNS configuration file
    #[clap(short, long, default_value = "/opt/dns/dns.toml")]
    config: String,

    /// Location of the DNS directory
    #[clap(short, long, default_value = "/opt/dns/")]
    directory: String,

    /// Logging level for the DNS server (e.g., debug, info, warn, error, trace)
    #[clap(short, long, default_value = "info")]
    log_level: String,

    /// Loging to journald, if available
    #[clap(short, long, default_value_t = false)]
    journald: bool,

    /// Port to listen on for web interface
    #[clap(short, long, default_value = "3000")]
    port: u16,

    /// Run with web interface
    #[clap(short, long, default_value_t = false)]
    webui: bool,
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
    let Args {
        config,
        directory,
        log_level,
        journald,
        port,
        webui,
    } = Args::parse();

    let reg = tracing_subscriber::registry();
    if journald {
        let layer = tracing_journald::layer().expect("Failed to create journald tracing");
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(parse_log_level(&log_level).into())
            .from_env_lossy();
        reg.with(layer).with(filter).init();
    } else {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(parse_log_level(&log_level).into())
            .from_env_lossy();
        reg.with(tracing_subscriber::fmt::layer())
            .with(filter)
            .init();
    }

    std::panic::set_hook(Box::new(|p| {
        error!("DNS server panic: {p:?}");
        std::process::exit(1);
    }));

    // let config = config.as_str();
    info!("Starting DNS server with config: {config}");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    _ = rt.block_on(async {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        if webui {
            tokio::spawn({
                let config = config.clone();
                async move {
                    if let Err(e) = lib::run_web(config, directory, port, tx).await {
                        error!("Web UI failed: {e}");
                    }
                }
            });
        }

        lib::run(config, rx).await
    });

    Ok(())
}
