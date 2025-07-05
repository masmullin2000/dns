#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod config;
mod dns_cache;
mod server;

use std::sync::{Arc, RwLock};

use config::RuntimeConfig;
use dns_cache::Cache;
use server::{tcp_server, udp_server};
use tracing::{error, info};

pub async fn run(cfg_str: &str) -> anyhow::Result<()> {
    let config: RuntimeConfig = std::fs::read_to_string(cfg_str)?.parse()?;
    let config = Arc::new(config);
    info!("Loaded DNS configuration from {cfg_str}");

    let cache: Cache = Cache::default();
    let cache = Arc::new(RwLock::new(cache));

    let cache_clone = cache.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Ok(mut cache) = cache_clone.write() {
                cache.prune();
            }
        }
    });

    let cfg = config.clone();
    let csh = cache.clone();
    tokio::spawn(async move {
        if let Err(e) = udp_server(cfg, csh) {
            error!("UDP server failed: {e}");
        }
    });
    tcp_server(config, cache)
        .await
        .inspect_err(|e| error!("TCP server failed: {e}"))
}

#[cfg(test)]
mod tests;
