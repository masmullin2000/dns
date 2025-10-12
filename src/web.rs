mod dot;
mod local_domains;
mod local_network;
mod nameservers;

pub use dot::{delete_dot, edit_dot, move_dot, save_dot, update_dot};
pub use local_domains::{
    delete_local_domain, edit_local_domains, save_local_domain, update_local_domain,
};
pub use local_network::{
    delete_local_network, edit_local_network, save_local_network, update_local_network,
};
pub use nameservers::{delete_nameservers, edit_nameservers, save_nameservers, update_nameservers};

use std::net::SocketAddr;

use crate::config::StartupConfig;
use askama::Template;
use axum::{
    Form,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use tower_http::services::ServeDir;
use tracing::{error, info};

pub async fn run_web(
    config: String,
    dir: String,
    port: u16,
    reset_sender: tokio::sync::mpsc::Sender<()>,
) -> anyhow::Result<()> {
    // Initialize tracing
    let app_state = AppState::new(config, reset_sender);

    let static_path = format!("{dir}/static");

    // Build application routes
    let app = Router::new()
        .route("/", get(index))
        .route("/config", get(view_config))
        .route("/config/edit", get(edit_config))
        .route("/config/save", post(save_config))
        .route("/restart", post(restart_dns))
        .route("/edit/options", get(edit_options))
        .route("/edit/options/save", post(save_options))
        .route("/edit/local_network", get(edit_local_network))
        .route("/edit/local_network/save", post(save_local_network))
        .route("/edit/local_network/update", post(update_local_network))
        .route("/edit/local_network/delete", post(delete_local_network))
        .route("/edit/local_domains", get(edit_local_domains))
        .route("/edit/local_domains/save", post(save_local_domain))
        .route("/edit/local_domains/update", post(update_local_domain))
        .route("/edit/local_domains/delete", post(delete_local_domain))
        .route("/edit/nameservers", get(edit_nameservers))
        .route("/edit/nameservers/save", post(save_nameservers))
        .route("/edit/nameservers/update", post(update_nameservers))
        .route("/edit/nameservers/delete", post(delete_nameservers))
        .route("/edit/dot", get(edit_dot))
        .route("/edit/dot/save", post(save_dot))
        .route("/edit/dot/update", post(update_dot))
        .route("/edit/dot/delete", post(delete_dot))
        .route("/edit/dot/move", post(move_dot))
        .nest_service("/static", ServeDir::new(static_path))
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("DNS Web UI listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Helper function to render templates with proper error handling
fn render_template<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Template rendering failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template rendering error: {e}"),
            )
                .into_response()
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    config_path: Arc<String>,
    config_content: Arc<RwLock<String>>,
    reset_sender: tokio::sync::mpsc::Sender<()>,
}

impl AppState {
    #[must_use]
    pub fn new(config_path: String, reset_sender: tokio::sync::mpsc::Sender<()>) -> Self {
        let content = std::fs::read_to_string(&config_path).unwrap_or_else(|_| {
            // Create a valid default configuration if file doesn't exist
            toml::to_string_pretty(&StartupConfig::default())
                .unwrap_or_else(|_| String::from("[local_network]\n"))
        });

        Self {
            config_path: Arc::new(config_path),
            config_content: Arc::new(RwLock::new(content)),
            reset_sender,
        }
    }

    pub fn reload_config(&self) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(self.config_path.as_ref())?;
        *self
            .config_content
            .write()
            .expect("reload_config: lock is poisoned") = content;
        Ok(())
    }

    #[must_use]
    pub fn get_config(&self) -> String {
        self.config_content
            .read()
            .expect("get_config: lock is poisoned")
            .clone()
    }

    pub fn save_config(&self, content: &str) -> anyhow::Result<()> {
        info!("Writing config to file: {}", self.config_path.as_ref());
        std::fs::write(self.config_path.as_ref(), content)?;
        *self
            .config_content
            .write()
            .expect("save_config: lock is poisoned") = content.to_string();
        info!("Config file written successfully");
        Ok(())
    }

    pub fn parse_config(&self) -> anyhow::Result<StartupConfig> {
        let content = self.get_config();
        content.parse()
    }

    pub fn update_config(&self, new_config: &StartupConfig) -> anyhow::Result<()> {
        info!("Converting config to TOML string");
        let toml_str = toml::to_string_pretty(new_config)?;
        info!("TOML serialization successful, {} bytes", toml_str.len());
        self.save_config(&toml_str)
    }
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    title: String,
}

#[derive(Template)]
#[template(path = "config_view.html")]
struct ConfigViewTemplate {
    config_content: String,
}

#[derive(Template)]
#[template(path = "config_edit.html")]
struct ConfigEditTemplate {
    config_content: String,
}

#[derive(Deserialize)]
pub struct ConfigForm {
    content: String,
}

#[derive(Template)]
#[template(path = "edit_options.html")]
struct EditOptionsTemplate {
    dot: String,
    blocklist_dir: String,
}

#[derive(Deserialize)]
pub struct OptionsForm {
    dot: String,
    blocklist_dir: String,
}

pub async fn index() -> impl IntoResponse {
    let template = IndexTemplate {
        title: "DNS Configuration Manager".to_string(),
    };
    render_template(template)
}

pub async fn view_config(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = state.reload_config() {
        error!("Failed to reload config: {e}");
    }

    let template = ConfigViewTemplate {
        config_content: state.get_config(),
    };
    render_template(template)
}

pub async fn edit_config(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = state.reload_config() {
        error!("Failed to reload config: {e}");
    }

    let template = ConfigEditTemplate {
        config_content: state.get_config(),
    };
    render_template(template)
}

pub async fn save_config(
    State(state): State<AppState>,
    Form(form): Form<ConfigForm>,
) -> impl IntoResponse {
    match state.save_config(&form.content) {
        Ok(()) => {
            info!("Configuration saved successfully");
            Redirect::to("/config")
        }
        Err(e) => {
            error!("Failed to save config: {e}");
            Redirect::to("/config/edit")
        }
    }
}

pub async fn restart_dns(State(state): State<AppState>) -> impl IntoResponse {
    info!("DNS restart requested via web UI");

    if let Err(e) = state.reset_sender.send(()).await {
        error!("Failed to send restart signal: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to restart DNS server",
        )
            .into_response();
    }

    (
        StatusCode::OK,
        "DNS server restart initiated. Configuration will be reloaded.",
    )
        .into_response()
}

// Options handlers
pub async fn edit_options(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let template = EditOptionsTemplate {
        dot: config.options.dot,
        blocklist_dir: config.options.blocklist_dir.unwrap_or_default(),
    };
    render_template(template)
}

pub async fn save_options(
    State(state): State<AppState>,
    Form(form): Form<OptionsForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/options");
        }
    };

    // Validate the dot setting
    let dot_value = match form.dot.as_str() {
        "off" | "on" | "force" => form.dot,
        _ => {
            error!("Invalid dot setting: {}", form.dot);
            return Redirect::to("/edit/options");
        }
    };

    config.options.dot = dot_value;

    // Update blocklist directory
    let blocklist_dir = form.blocklist_dir.trim();
    config.options.blocklist_dir = if blocklist_dir.is_empty() {
        None
    } else {
        Some(blocklist_dir.to_string())
    };

    match state.update_config(&config) {
        Ok(()) => {
            info!("Options saved successfully");
            Redirect::to("/")
        }
        Err(e) => {
            error!("Failed to save options: {e}");
            Redirect::to("/edit/options")
        }
    }
}
