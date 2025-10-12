#![allow(
    clippy::cognitive_complexity,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

pub mod config;
pub mod web;

mod block_filter;
mod dns_cache;
mod dot_client;
mod server;

use std::sync::{Arc, RwLock};

use config::{RuntimeConfig, StartupConfig};
use server::{tcp_server, udp_server};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub use web::run_web;

const DEFAULT_NS_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(1, 1, 1, 1);
const DEFAULT_NS: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(DEFAULT_NS_IP), 53);

pub async fn run(
    config_path: impl AsRef<str>,
    mut reset_recv: tokio::sync::mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let config_path = config_path.as_ref();

    // Preserve cache across reloads
    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));

    loop {
        // Load configuration
        let config: StartupConfig = std::fs::read_to_string(config_path)
            .inspect(|_| info!("Reading configuration file: {config_path}"))
            .unwrap_or_else(|_| {
                // Create a valid default configuration if file doesn't exist
                info!("Configuration file not found, loading default configuration");
                toml::to_string_pretty(&StartupConfig::default())
                    .unwrap_or_else(|_| String::from("[local_network]\n"))
            })
            .parse()?;

        let mut config: RuntimeConfig = config.into();
        if config.nameservers.is_empty() {
            warn!(
                "No valid nameservers configured, configuring with Cloudflare DNS at {DEFAULT_NS}"
            );
            config.nameservers.push(DEFAULT_NS); // Default to Cloudflare DNS
        }
        let config = Arc::new(config);

        // Create cancellation token for this server instance
        let shutdown_token = CancellationToken::new();

        // Start servers
        if let Err(e) = udp_server(config.clone(), cache.clone(), shutdown_token.clone()) {
            error!("UDP server failed: {e}");
            std::process::exit(1);
        }
        if let Err(e) = tcp_server(config.clone(), cache.clone(), shutdown_token.clone()).await {
            error!("TCP server failed: {e}");
            std::process::exit(1);
        }

        // Cache pruning and signal handling
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        let reload_signal = shutdown_token.clone();

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Ok(mut cache) = cache.write() {
                        cache.prune();
                    }
                }
                _ = reset_recv.recv() => {
                    info!("Received reset signal, reloading configuration...");
                    reload_signal.cancel();
                    break;
                }
            }
        }

        // Give servers time to shutdown gracefully
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        info!("Servers stopped, reloading configuration...");

        // Clear the DoT connection pool on reload
        warn!("Configuration reloaded successfully");
    }
}

#[cfg(test)]
mod tests;
