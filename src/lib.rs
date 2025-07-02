#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

mod config;
mod server;
mod dns_cache;

use std::sync::{Arc, RwLock};

use config::Config;
use server::{tcp_server, udp_server};
use dns_cache::Cache;

pub async fn run(cfg_str: &str) -> anyhow::Result<()> {
    let config: Config = std::fs::read_to_string(cfg_str)?.parse()?;
    let config = Arc::new(config);

    let cache: Cache = Cache::default();
    let cache = Arc::new(RwLock::new(cache));

    let cfg = config.clone();
    let csh = cache.clone();
    tokio::spawn(async move {
        udp_server(cfg, csh).expect("udp_server failed");
    });
    tcp_server(config, cache).await
}
