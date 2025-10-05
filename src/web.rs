use axum::{
    Router,
    routing::{get, post},
};
use clap::Parser;
use std::net::SocketAddr;
use tracing::{Level, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod web_ui;

#[derive(Parser)]
struct Args {
    /// Location of the DNS configuration file
    #[clap(short, long, default_value = "/opt/dns/dns.toml")]
    config: String,

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(parse_log_level(&args.log_level).into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    let app_state = web_ui::AppState::new(args.config);

    // Build application routes
    let app = Router::new()
        .route("/", get(web_ui::index))
        .route("/config", get(web_ui::view_config))
        .route("/config/edit", get(web_ui::edit_config))
        .route("/config/save", post(web_ui::save_config))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("DNS Web UI listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
