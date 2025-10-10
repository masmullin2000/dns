mod dot;
mod local_domains;
mod local_network;

pub use dot::{edit_dot, save_dot, update_dot, delete_dot, move_dot};
pub use local_domains::{
    edit_local_domains, save_local_domain, update_local_domain, delete_local_domain,
};
pub use local_network::{
    edit_local_network, save_local_network, update_local_network, delete_local_network,
};

use askama::Template;
use axum::{
    Form,
    extract::State,
    response::{Html, IntoResponse, Redirect},
};
use lib::config::StartupConfig;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use tracing::{error, info};

#[derive(Clone)]
pub struct AppState {
    config_path: Arc<String>,
    config_content: Arc<RwLock<String>>,
}

impl AppState {
    pub fn new(config_path: String) -> Self {
        let content = std::fs::read_to_string(&config_path)
            .unwrap_or_else(|_| String::from("# Failed to load config"));

        Self {
            config_path: Arc::new(config_path),
            config_content: Arc::new(RwLock::new(content)),
        }
    }

    pub fn reload_config(&self) -> anyhow::Result<()> {
        let content = std::fs::read_to_string(self.config_path.as_ref())?;
        *self.config_content.write().unwrap() = content;
        Ok(())
    }

    pub fn get_config(&self) -> String {
        self.config_content.read().unwrap().clone()
    }

    pub fn save_config(&self, content: &str) -> anyhow::Result<()> {
        info!("Writing config to file: {}", self.config_path.as_ref());
        std::fs::write(self.config_path.as_ref(), content)?;
        *self.config_content.write().unwrap() = content.to_string();
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
    force_dot: bool,
}

#[derive(Deserialize)]
pub struct OptionsForm {
    force_dot: Option<String>,
}


#[derive(Template)]
#[template(path = "edit_blocklists.html")]
struct EditBlocklistsTemplate {
    content: String,
}

#[derive(Template)]
#[template(path = "edit_nameservers.html")]
struct EditNameserversTemplate {
    content: String,
}


pub async fn index() -> impl IntoResponse {
    let template = IndexTemplate {
        title: "DNS Configuration Manager".to_string(),
    };
    Html(template.render().unwrap())
}

pub async fn view_config(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = state.reload_config() {
        error!("Failed to reload config: {e}");
    }

    let template = ConfigViewTemplate {
        config_content: state.get_config(),
    };
    Html(template.render().unwrap())
}

pub async fn edit_config(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = state.reload_config() {
        error!("Failed to reload config: {e}");
    }

    let template = ConfigEditTemplate {
        config_content: state.get_config(),
    };
    Html(template.render().unwrap())
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

// Options handlers
pub async fn edit_options(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let template = EditOptionsTemplate {
        force_dot: config.options.force_dot,
    };
    Html(template.render().unwrap())
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

    config.options.force_dot = form.force_dot.is_some();

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

// Blocklists handlers
pub async fn edit_blocklists(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let content = config.blocklists.files.unwrap_or_default().join("\n");

    let template = EditBlocklistsTemplate { content };
    Html(template.render().unwrap())
}

pub async fn save_blocklists(
    State(state): State<AppState>,
    Form(form): Form<ConfigForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/blocklists");
        }
    };

    let files: Vec<String> = form
        .content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    config.blocklists.files = if files.is_empty() { None } else { Some(files) };

    match state.update_config(&config) {
        Ok(()) => {
            info!("Blocklists saved successfully");
            Redirect::to("/")
        }
        Err(e) => {
            error!("Failed to save blocklists: {e}");
            Redirect::to("/edit/blocklists")
        }
    }
}

// Nameservers handlers
pub async fn edit_nameservers(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let ips: Vec<String> = config.nameservers.ip4.iter().cloned().collect();
    let content = ips.join("\n");

    let template = EditNameserversTemplate { content };
    Html(template.render().unwrap())
}

pub async fn save_nameservers(
    State(state): State<AppState>,
    Form(form): Form<ConfigForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/nameservers");
        }
    };

    config.nameservers.ip4.clear();
    for line in form.content.lines() {
        let line = line.trim();
        if !line.is_empty() {
            config.nameservers.ip4.insert(line.to_string());
        }
    }

    match state.update_config(&config) {
        Ok(()) => {
            info!("Nameservers saved successfully");
            Redirect::to("/")
        }
        Err(e) => {
            error!("Failed to save nameservers: {e}");
            Redirect::to("/edit/nameservers")
        }
    }
}

