use askama::Template;
use axum::{
    Form,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use tracing::{error, info};

use crate::config;

use super::AppState;

fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers.get("hx-request").is_some()
}

fn get_dot_servers_from_config(state: &AppState) -> Vec<DotServerEntry> {
    let config = state.parse_config().unwrap_or_default();
    config
        .nameservers
        .dot
        .unwrap_or_default()
        .iter()
        .map(|s| DotServerEntry {
            hostname: s.hostname.clone(),
            ip: s.ip.to_string(),
            port: s.port,
        })
        .collect()
}

#[derive(Deserialize)]
pub struct DotServerForm {
    hostname: String,
    ip: String,
    port: u16,
}

#[derive(Deserialize)]
pub struct DeleteDotServerForm {
    remove_hostname: String,
}

#[derive(Deserialize)]
pub struct MoveDotServerForm {
    hostname: String,
    direction: String, // "up" or "down"
}

#[derive(Deserialize)]
pub struct UpdateDotServerForm {
    old_hostname: String,
    new_hostname: String,
    new_ip: String,
    new_port: u16,
}

#[derive(Template)]
#[template(path = "edit_dot.html")]
struct EditDotTemplate {
    entries: Vec<DotServerEntry>,
}

#[derive(Template)]
#[template(path = "dot_table.html")]
struct DotTableTemplate {
    entries: Vec<DotServerEntry>,
}

#[derive(Clone)]
struct DotServerEntry {
    hostname: String,
    ip: String,
    port: u16,
}

pub async fn edit_dot(State(state): State<AppState>) -> impl IntoResponse {
    let entries = get_dot_servers_from_config(&state);
    let template = EditDotTemplate { entries };
    super::render_template(template)
}

pub async fn save_dot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DotServerForm>,
) -> impl IntoResponse {
    let hostname = form.hostname.trim();
    let ip_str = form.ip.trim();

    info!(
        "save_dot called with hostname='{}', ip='{}', port={}",
        hostname, ip_str, form.port
    );

    if hostname.is_empty() || ip_str.is_empty() {
        error!("Hostname or IP address is empty");
        if is_htmx_request(&headers) {
            let entries = get_dot_servers_from_config(&state);
            let template = DotTableTemplate { entries };
            return super::render_template(template).into_response();
        }
        return Redirect::to("/edit/dot").into_response();
    }

    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/dot").into_response();
        }
    };

    let ip = match ip_str.parse() {
        Ok(ip) => ip,
        Err(e) => {
            error!("Invalid IP address '{}': {}", ip_str, e);
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/dot").into_response();
        }
    };

    // Get existing servers or create new vec
    let mut servers = config.nameservers.dot.unwrap_or_default();

    // Check if server with this hostname already exists
    if servers.iter().any(|s| s.hostname == hostname) {
        error!("DoT server with hostname '{}' already exists", hostname);
        if is_htmx_request(&headers) {
            let entries = get_dot_servers_from_config(&state);
            let template = DotTableTemplate { entries };
            return super::render_template(template).into_response();
        }
        return Redirect::to("/edit/dot").into_response();
    }

    servers.push(config::DotServer {
        hostname: hostname.to_string(),
        ip,
        port: form.port,
    });
    config.nameservers.dot = Some(servers);
    info!("Added DoT server: {} = {}:{}", hostname, ip, form.port);

    match state.update_config(&config) {
        Ok(()) => {
            info!("Successfully saved DoT server entry");
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                super::render_template(template).into_response()
            } else {
                Redirect::to("/edit/dot").into_response()
            }
        }
        Err(e) => {
            error!("Failed to save DoT configuration: {e}");
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                super::render_template(template).into_response()
            } else {
                Redirect::to("/edit/dot").into_response()
            }
        }
    }
}

pub async fn update_dot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateDotServerForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/dot").into_response();
        }
    };

    let mut servers = config.nameservers.dot.unwrap_or_default();

    // Find and update the server
    if let Some(pos) = servers.iter().position(|s| s.hostname == form.old_hostname) {
        if let Ok(ip) = form.new_ip.parse() {
            servers[pos] = config::DotServer {
                hostname: form.new_hostname.clone(),
                ip,
                port: form.new_port,
            };
            config.nameservers.dot = Some(servers);

            match state.update_config(&config) {
                Ok(()) => {
                    info!(
                        "Updated DoT server: {} -> {} = {}:{}",
                        form.old_hostname, form.new_hostname, form.new_ip, form.new_port
                    );
                    if is_htmx_request(&headers) {
                        let entries = get_dot_servers_from_config(&state);
                        let template = DotTableTemplate { entries };
                        super::render_template(template).into_response()
                    } else {
                        Redirect::to("/edit/dot").into_response()
                    }
                }
                Err(e) => {
                    error!("Failed to save config after update: {e}");
                    if is_htmx_request(&headers) {
                        let entries = get_dot_servers_from_config(&state);
                        let template = DotTableTemplate { entries };
                        super::render_template(template).into_response()
                    } else {
                        Redirect::to("/edit/dot").into_response()
                    }
                }
            }
        } else {
            error!("Invalid IP address: {}", form.new_ip);
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                super::render_template(template).into_response()
            } else {
                Redirect::to("/edit/dot").into_response()
            }
        }
    } else {
        error!("DoT server not found: {}", form.old_hostname);
        if is_htmx_request(&headers) {
            let entries = get_dot_servers_from_config(&state);
            let template = DotTableTemplate { entries };
            super::render_template(template).into_response()
        } else {
            Redirect::to("/edit/dot").into_response()
        }
    }
}

pub async fn delete_dot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteDotServerForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/dot").into_response();
        }
    };

    let mut servers = config.nameservers.dot.unwrap_or_default();

    // Remove the specified server
    if let Some(pos) = servers
        .iter()
        .position(|s| s.hostname == form.remove_hostname)
    {
        servers.remove(pos);
        config.nameservers.dot = if servers.is_empty() {
            None
        } else {
            Some(servers)
        };

        match state.update_config(&config) {
            Ok(()) => {
                info!("Removed DoT server: {}", form.remove_hostname);
                if is_htmx_request(&headers) {
                    let entries = get_dot_servers_from_config(&state);
                    let template = DotTableTemplate { entries };
                    super::render_template(template).into_response()
                } else {
                    Redirect::to("/edit/dot").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after deletion: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_dot_servers_from_config(&state);
                    let template = DotTableTemplate { entries };
                    super::render_template(template).into_response()
                } else {
                    Redirect::to("/edit/dot").into_response()
                }
            }
        }
    } else {
        error!("DoT server not found: {}", form.remove_hostname);
        if is_htmx_request(&headers) {
            let entries = get_dot_servers_from_config(&state);
            let template = DotTableTemplate { entries };
            super::render_template(template).into_response()
        } else {
            Redirect::to("/edit/dot").into_response()
        }
    }
}

pub async fn move_dot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MoveDotServerForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/dot").into_response();
        }
    };

    let mut servers = config.nameservers.dot.unwrap_or_default();

    // Find the server to move
    if let Some(current_pos) = servers.iter().position(|s| s.hostname == form.hostname) {
        let can_move_up = current_pos > 0;
        let can_move_down = current_pos < servers.len() - 1;

        let should_move = match form.direction.as_str() {
            "up" => can_move_up,
            "down" => can_move_down,
            _ => false,
        };

        if should_move {
            let new_pos = match form.direction.as_str() {
                "up" => current_pos - 1,
                "down" => current_pos + 1,
                _ => current_pos,
            };

            // Swap positions
            servers.swap(current_pos, new_pos);
            config.nameservers.dot = Some(servers);

            match state.update_config(&config) {
                Ok(()) => {
                    info!("Moved DoT server {} {}", form.hostname, form.direction);
                    if is_htmx_request(&headers) {
                        let entries = get_dot_servers_from_config(&state);
                        let template = DotTableTemplate { entries };
                        super::render_template(template).into_response()
                    } else {
                        Redirect::to("/edit/dot").into_response()
                    }
                }
                Err(e) => {
                    error!("Failed to save config after move: {e}");
                    if is_htmx_request(&headers) {
                        let entries = get_dot_servers_from_config(&state);
                        let template = DotTableTemplate { entries };
                        super::render_template(template).into_response()
                    } else {
                        Redirect::to("/edit/dot").into_response()
                    }
                }
            }
        } else {
            // Can't move in that direction (already at boundary)
            if is_htmx_request(&headers) {
                let entries = get_dot_servers_from_config(&state);
                let template = DotTableTemplate { entries };
                super::render_template(template).into_response()
            } else {
                Redirect::to("/edit/dot").into_response()
            }
        }
    } else {
        error!("DoT server not found: {}", form.hostname);
        if is_htmx_request(&headers) {
            let entries = get_dot_servers_from_config(&state);
            let template = DotTableTemplate { entries };
            super::render_template(template).into_response()
        } else {
            Redirect::to("/edit/dot").into_response()
        }
    }
}
