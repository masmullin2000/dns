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

fn get_entries_from_config(state: &AppState) -> Vec<NameserverEntry> {
    let config = state.parse_config().unwrap_or_default();
    config
        .nameservers
        .ip4
        .iter()
        .map(|ip| NameserverEntry { ip: ip.clone() })
        .collect()
}

#[derive(Deserialize)]
pub struct NameserverForm {
    ip: String,
}

#[derive(Deserialize)]
pub struct DeleteNameserverForm {
    remove_ip: String,
}

#[derive(Deserialize)]
pub struct UpdateNameserverForm {
    old_ip: String,
    new_ip: String,
}

#[derive(Template)]
#[template(path = "edit_nameservers.html")]
struct EditNameserversTemplate {
    entries: Vec<NameserverEntry>,
}

#[derive(Template)]
#[template(path = "nameservers_table.html")]
struct NameserversTableTemplate {
    entries: Vec<NameserverEntry>,
}

#[derive(Clone)]
struct NameserverEntry {
    ip: String,
}

pub async fn edit_nameservers(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.parse_config().unwrap_or_default();
    let entries = config
        .nameservers
        .ip4
        .iter()
        .map(|ip| NameserverEntry { ip: ip.clone() })
        .collect();

    let template = EditNameserversTemplate { entries };
    Html(template.render().unwrap())
}

pub async fn save_nameservers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<NameserverForm>,
) -> impl IntoResponse {
    let ip_str = form.ip.trim();

    info!("save_nameservers called with ip='{}'", ip_str);

    if ip_str.is_empty() {
        error!("IP address is empty");
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = NameserversTableTemplate { entries };
            return Html(template.render().unwrap()).into_response();
        }
        return Redirect::to("/edit/nameservers").into_response();
    }

    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = NameserversTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/nameservers").into_response();
        }
    };

    info!(
        "Current nameservers has {} entries before adding",
        config.nameservers.ip4.len()
    );

    // Validate IP address
    if ip_str.parse::<std::net::IpAddr>().is_err() {
        error!("Invalid IP address '{}'", ip_str);
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = NameserversTableTemplate { entries };
            return Html(template.render().unwrap()).into_response();
        }
        return Redirect::to("/edit/nameservers").into_response();
    }

    config.nameservers.ip4.insert(ip_str.to_string());
    info!("Added nameserver entry: {}", ip_str);

    match state.update_config(&config) {
        Ok(()) => {
            info!("Successfully saved nameserver entry");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = NameserversTableTemplate { entries };
                Html(template.render().unwrap()).into_response()
            } else {
                Redirect::to("/edit/nameservers").into_response()
            }
        }
        Err(e) => {
            error!("Failed to save nameservers: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = NameserversTableTemplate { entries };
                Html(template.render().unwrap()).into_response()
            } else {
                Redirect::to("/edit/nameservers").into_response()
            }
        }
    }
}

pub async fn update_nameservers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateNameserverForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = NameserversTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/nameservers").into_response();
        }
    };

    // Remove old IP entry
    config.nameservers.ip4.remove(&form.old_ip);

    // Validate new IP address
    if form.new_ip.parse::<std::net::IpAddr>().is_ok() {
        config.nameservers.ip4.insert(form.new_ip.clone());

        match state.update_config(&config) {
            Ok(()) => {
                info!(
                    "Updated nameserver entry: {} -> {}",
                    form.old_ip, form.new_ip
                );
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = NameserversTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/nameservers").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after update: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = NameserversTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/nameservers").into_response()
                }
            }
        }
    } else {
        error!("Invalid IP address: {}", form.new_ip);
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = NameserversTableTemplate { entries };
            Html(template.render().unwrap()).into_response()
        } else {
            Redirect::to("/edit/nameservers").into_response()
        }
    }
}

pub async fn delete_nameservers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteNameserverForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_entries_from_config(&state);
                let template = NameserversTableTemplate { entries };
                return Html(template.render().unwrap()).into_response();
            }
            return Redirect::to("/edit/nameservers").into_response();
        }
    };

    // Remove the specified IP
    if config.nameservers.ip4.remove(&form.remove_ip) {
        match state.update_config(&config) {
            Ok(()) => {
                info!("Removed nameserver entry: {}", form.remove_ip);
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = NameserversTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/nameservers").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after deletion: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_entries_from_config(&state);
                    let template = NameserversTableTemplate { entries };
                    Html(template.render().unwrap()).into_response()
                } else {
                    Redirect::to("/edit/nameservers").into_response()
                }
            }
        }
    } else {
        error!("IP not found: {}", form.remove_ip);
        if is_htmx_request(&headers) {
            let entries = get_entries_from_config(&state);
            let template = NameserversTableTemplate { entries };
            Html(template.render().unwrap()).into_response()
        } else {
            Redirect::to("/edit/nameservers").into_response()
        }
    }
}
