#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

mod block_filter;
pub mod config;
mod dns_cache;
mod dot_client;
mod server;

use std::sync::{Arc, RwLock};

use config::{RuntimeConfig, StartupConfig};
use server::{tcp_server, udp_server};
use tracing::{error, info};

pub async fn run(cfg_str: impl AsRef<str>) -> anyhow::Result<()> {
    let cfg_str = cfg_str.as_ref();
    let config: StartupConfig = std::fs::read_to_string(cfg_str)?.parse()?;
    let config: RuntimeConfig = config.into();
    let config = Arc::new(config);
    info!("Loaded DNS configuration from {cfg_str}");

    let cache = Arc::new(RwLock::new(dns_cache::Cache::default()));

    if let Err(e) = udp_server(config.clone(), cache.clone()) {
        error!("UDP server failed: {e}");
        std::process::exit(1);
    }
    if let Err(e) = tcp_server(config.clone(), cache.clone()).await {
        error!("TCP server failed: {e}");
        std::process::exit(1);
    }

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
