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

#[derive(Deserialize)]
pub struct LocalNetworkForm {
    hostname: String,
    ip: String,
}

#[derive(Deserialize)]
pub struct DeleteLocalNetworkForm {
    remove_hostname: String,
}

#[derive(Deserialize)]
pub struct UpdateLocalNetworkForm {
    old_hostname: String,
    new_hostname: String,
    new_ip: String,
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
#[template(path = "edit_local_network.html")]
struct EditLocalNetworkTemplate {
    entries: Vec<NetworkEntry>,
}

#[derive(Clone)]
struct NetworkEntry {
    hostname: String,
    ip: String,
}

#[derive(Template)]
#[template(path = "edit_local_domains.html")]
struct EditLocalDomainsTemplate {
    content: String,
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

#[derive(Template)]
#[template(path = "edit_dot.html")]
struct EditDotTemplate {
    servers: Vec<DotServerDisplay>,
}

#[derive(Clone)]
struct DotServerDisplay {
    hostname: String,
    ip: String,
    port: u16,
}

#[derive(Deserialize)]
pub struct DotForm {
    hostname: Vec<String>,
    ip: Vec<String>,
    port: Vec<u16>,
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

// Local network handlers
pub async fn edit_local_network(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let entries = config
        .local_network
        .hosts
        .iter()
        .map(|(hostname, ip)| NetworkEntry {
            hostname: hostname.clone(),
            ip: ip.to_string(),
        })
        .collect();

    let template = EditLocalNetworkTemplate { entries };
    Html(template.render().unwrap())
}

pub async fn save_local_network(
    State(state): State<AppState>,
    Form(form): Form<LocalNetworkForm>,
) -> impl IntoResponse {
    let hostname = form.hostname.trim();
    let ip_str = form.ip.trim();

    info!(
        "save_local_network called with hostname='{}', ip='{}'",
        hostname, ip_str
    );

    if hostname.is_empty() || ip_str.is_empty() {
        error!("Hostname or IP address is empty");
        return Redirect::to("/edit/local_network");
    }

    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/local_network");
        }
    };

    info!(
        "Current local_network has {} entries before adding",
        config.local_network.hosts.len()
    );

    let ip = match ip_str.parse() {
        Ok(ip) => ip,
        Err(e) => {
            error!("Invalid IP address '{}': {}", ip_str, e);
            return Redirect::to("/edit/local_network");
        }
    };

    config.local_network.hosts.insert(hostname.to_string(), ip);
    info!("Added local network entry: {} = {}", hostname, ip);

    match state.update_config(&config) {
        Ok(()) => {
            info!("Successfully saved local network entry");
            Redirect::to("/edit/local_network")
        }
        Err(e) => {
            error!("Failed to save local network: {e}");
            Redirect::to("/edit/local_network")
        }
    }
}

pub async fn update_local_network(
    State(state): State<AppState>,
    Form(form): Form<UpdateLocalNetworkForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/local_network");
        }
    };

    // Remove old hostname entry
    config.local_network.hosts.remove(&form.old_hostname);

    // Add updated entry with new hostname and IP
    if let Ok(ip) = form.new_ip.parse() {
        config
            .local_network
            .hosts
            .insert(form.new_hostname.clone(), ip);

        match state.update_config(&config) {
            Ok(()) => {
                info!(
                    "Updated local network entry: {} -> {} = {}",
                    form.old_hostname, form.new_hostname, form.new_ip
                );
                Redirect::to("/edit/local_network")
            }
            Err(e) => {
                error!("Failed to save config after update: {e}");
                Redirect::to("/edit/local_network")
            }
        }
    } else {
        error!("Invalid IP address: {}", form.new_ip);
        Redirect::to("/edit/local_network")
    }
}

pub async fn delete_local_network(
    State(state): State<AppState>,
    Form(form): Form<DeleteLocalNetworkForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/local_network");
        }
    };

    // Remove the specified hostname
    if config
        .local_network
        .hosts
        .remove(&form.remove_hostname)
        .is_some()
    {
        match state.update_config(&config) {
            Ok(()) => {
                info!("Removed local network entry: {}", form.remove_hostname);
                Redirect::to("/edit/local_network")
            }
            Err(e) => {
                error!("Failed to save config after deletion: {e}");
                Redirect::to("/edit/local_network")
            }
        }
    } else {
        error!("Hostname not found: {}", form.remove_hostname);
        Redirect::to("/edit/local_network")
    }
}

// Local domains handlers
pub async fn edit_local_domains(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let content = config.local_domains.domains.unwrap_or_default().join("\n");

    let template = EditLocalDomainsTemplate { content };
    Html(template.render().unwrap())
}

pub async fn save_local_domains(
    State(state): State<AppState>,
    Form(form): Form<ConfigForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/local_domains");
        }
    };

    let domains: Vec<String> = form
        .content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    config.local_domains.domains = if domains.is_empty() {
        None
    } else {
        Some(domains)
    };

    match state.update_config(&config) {
        Ok(()) => {
            info!("Local domains saved successfully");
            Redirect::to("/")
        }
        Err(e) => {
            error!("Failed to save local domains: {e}");
            Redirect::to("/edit/local_domains")
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

// DoT handlers
pub async fn edit_dot(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let servers = config
        .nameservers
        .dot
        .unwrap_or_default()
        .iter()
        .map(|s| DotServerDisplay {
            hostname: s.hostname.clone(),
            ip: s.ip.to_string(),
            port: s.port,
        })
        .collect();

    let template = EditDotTemplate { servers };
    Html(template.render().unwrap())
}

pub async fn save_dot(
    State(state): State<AppState>,
    Form(form): Form<DotForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            return Redirect::to("/edit/dot");
        }
    };

    let mut servers = Vec::new();
    for i in 0..form.hostname.len() {
        if let (Some(hostname), Some(ip_str), Some(port)) =
            (form.hostname.get(i), form.ip.get(i), form.port.get(i))
            && let Ok(ip) = ip_str.parse()
        {
            servers.push(lib::config::DotServer {
                hostname: hostname.clone(),
                ip,
                port: *port,
            });
        }
    }

    config.nameservers.dot = if servers.is_empty() {
        None
    } else {
        Some(servers)
    };

    match state.update_config(&config) {
        Ok(()) => {
            info!("DoT configuration saved successfully");
            Redirect::to("/")
        }
        Err(e) => {
            error!("Failed to save DoT configuration: {e}");
            Redirect::to("/edit/dot")
        }
    }
}
