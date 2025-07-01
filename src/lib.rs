#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

mod config;
mod server;

use std::sync::Arc;

use config::Config;
use server::{tcp_server, udp_server};

pub async fn run(cfg_str: &str) -> anyhow::Result<()> {
    let config: Config = std::fs::read_to_string(cfg_str)?.parse()?;
    let config = Arc::new(config);

    let cfg = config.clone();
    tokio::spawn(async move {
        udp_server(cfg).expect("udp_server failed");
    });
    tcp_server(config).await
}
