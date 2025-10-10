#![allow(clippy::cognitive_complexity)]

mod web_ui;

use std::net::SocketAddr;

use axum::{
    Router,
    routing::{get, post},
};
use clap::Parser;
use tower_http::services::ServeDir;
use tracing::{Level, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
        .route("/edit/options", get(web_ui::edit_options))
        .route("/edit/options/save", post(web_ui::save_options))
        .route("/edit/local_network", get(web_ui::edit_local_network))
        .route("/edit/local_network/save", post(web_ui::save_local_network))
        .route(
            "/edit/local_network/update",
            post(web_ui::update_local_network),
        )
        .route(
            "/edit/local_network/delete",
            post(web_ui::delete_local_network),
        )
        .route("/edit/local_domains", get(web_ui::edit_local_domains))
        .route("/edit/local_domains/save", post(web_ui::save_local_domain))
        .route(
            "/edit/local_domains/update",
            post(web_ui::update_local_domain),
        )
        .route(
            "/edit/local_domains/delete",
            post(web_ui::delete_local_domain),
        )
        .route("/edit/blocklists", get(web_ui::edit_blocklists))
        .route("/edit/blocklists/save", post(web_ui::save_blocklists))
        .route("/edit/nameservers", get(web_ui::edit_nameservers))
        .route("/edit/nameservers/save", post(web_ui::save_nameservers))
        .route("/edit/dot", get(web_ui::edit_dot))
        .route("/edit/dot/save", post(web_ui::save_dot))
        .route("/edit/dot/update", post(web_ui::update_dot))
        .route("/edit/dot/delete", post(web_ui::delete_dot))
        .route("/edit/dot/move", post(web_ui::move_dot))
        .nest_service("/static", ServeDir::new("static"))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("DNS Web UI listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
