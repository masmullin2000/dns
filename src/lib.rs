#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod config;
mod dns_cache;
mod server;

use std::sync::{Arc, RwLock};

use config::{RuntimeConfig, StartupConfig};
use server::{tcp_server, udp_server};
use tracing::{error, info};

pub async fn run(cfg_str: &str) -> anyhow::Result<()> {
    let config: StartupConfig = std::fs::read_to_string(cfg_str)?.parse()?;
    let config: RuntimeConfig = config.into();
    let config = Arc::new(config);
    info!("Loaded DNS configuration from {cfg_str}");

    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));

    tokio::spawn({
        let config = config.clone();
        let cache = cache.clone();
        async move { _ = udp_server(config, cache).inspect_err(|e| error!("UDP server failed: {e}")) }
    });
    tokio::spawn({
        let cache = cache.clone();
        async move {
            tcp_server(config, cache)
                .await
                .inspect_err(|e| error!("TCP server failed: {e}"))
        }
    });

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Ok(mut cache) = cache.write() {
            cache.prune();
        }
    }
}

#[cfg(test)]
mod tests;
