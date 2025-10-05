use askama::Template;
use axum::{
    Form,
    extract::State,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use tracing::{error, info};

use super::AppState;

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
#[template(path = "edit_local_network.html")]
struct EditLocalNetworkTemplate {
    entries: Vec<NetworkEntry>,
}

#[derive(Clone)]
struct NetworkEntry {
    hostname: String,
    ip: String,
}

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
