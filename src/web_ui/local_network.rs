use askama::Template;
use axum::{
    Form,
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use serde::Deserialize;
use tracing::{error, info};

use super::AppState;

fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers.get("hx-request").is_some()
}

fn get_entries_from_config(state: &AppState) -> Vec<NetworkEntry> {
    let config = state.parse_config().unwrap_or_default();
    config
        .local_network
        .hosts
        .iter()
        .map(|(hostname, ip)| NetworkEntry {
            hostname: hostname.clone(),
            ip: ip.to_string(),
        })
        .collect()
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
#[template(path = "edit_local_network.html")]
struct EditLocalNetworkTemplate {
    entries: Vec<NetworkEntry>,
}

#[derive(Template)]
#[template(path = "local_network_table.html")]
struct LocalNetworkTableTemplate {
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
    headers: HeaderMap,
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
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = LocalNetworkTableTemplate { entries };
            return Html(template.render().unwrap()).into_response();
        }
        return Redirect::to("/edit/local_network").into_response();
    }

    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = LocalNetworkTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/local_network").into_response();
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
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = LocalNetworkTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/local_network").into_response();
        }
    };

    config.local_network.hosts.insert(hostname.to_string(), ip);
    info!("Added local network entry: {} = {}", hostname, ip);

    match state.update_config(&config) {
        Ok(()) => {
            info!("Successfully saved local network entry");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = LocalNetworkTableTemplate { entries };
                Html(template.render().unwrap()).into_response()
            } else {
                Redirect::to("/edit/local_network").into_response()
            }
        }
        Err(e) => {
            error!("Failed to save local network: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = LocalNetworkTableTemplate { entries };
                Html(template.render().unwrap()).into_response()
            } else {
                Redirect::to("/edit/local_network").into_response()
            }
        }
    }
}

pub async fn update_local_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateLocalNetworkForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = LocalNetworkTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/local_network").into_response();
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
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = LocalNetworkTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/local_network").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after update: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = LocalNetworkTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/local_network").into_response()
                }
            }
        }
    } else {
        error!("Invalid IP address: {}", form.new_ip);
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = LocalNetworkTableTemplate { entries };
            Html(template.render().unwrap()).into_response()
        } else {
            Redirect::to("/edit/local_network").into_response()
        }
    }
}

pub async fn delete_local_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteLocalNetworkForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = LocalNetworkTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/local_network").into_response();
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
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = LocalNetworkTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/local_network").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after deletion: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = LocalNetworkTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/local_network").into_response()
                }
            }
        }
    } else {
        error!("Hostname not found: {}", form.remove_hostname);
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = LocalNetworkTableTemplate { entries };
            Html(template.render().unwrap()).into_response()
        } else {
            Redirect::to("/edit/local_network").into_response()
        }
    }
}
