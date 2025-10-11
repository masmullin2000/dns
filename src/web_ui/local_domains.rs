use askama::Template;
use axum::{
    Form,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect},
};
use serde::Deserialize;
use tracing::{error, info};

use super::AppState;

fn is_htmx_request(headers: &HeaderMap) -> bool {
    headers.get("hx-request").is_some()
}

fn get_domains_from_config(state: &AppState) -> Vec<DomainEntry> {
    let config = state.parse_config().unwrap_or_default();
    config
        .local_domains
        .domains
        .unwrap_or_default()
        .iter()
        .map(|domain| DomainEntry {
            domain: domain.clone(),
        })
        .collect()
}

#[derive(Deserialize)]
pub struct LocalDomainForm {
    domain: String,
}

#[derive(Deserialize)]
pub struct DeleteLocalDomainForm {
    remove_domain: String,
}

#[derive(Deserialize)]
pub struct UpdateLocalDomainForm {
    old_domain: String,
    new_domain: String,
}

#[derive(Template)]
#[template(path = "edit_local_domains.html")]
struct EditLocalDomainsTemplate {
    entries: Vec<DomainEntry>,
}

#[derive(Template)]
#[template(path = "local_domains_table.html")]
struct LocalDomainsTableTemplate {
    entries: Vec<DomainEntry>,
}

#[derive(Clone)]
struct DomainEntry {
    domain: String,
}

pub async fn edit_local_domains(State(state): State<AppState>) -> impl IntoResponse {
    let entries = get_domains_from_config(&state);
    let template = EditLocalDomainsTemplate { entries };
    super::render_template(template)
}

pub async fn save_local_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LocalDomainForm>,
) -> impl IntoResponse {
    let domain = form.domain.trim();

    info!("save_local_domain called with domain='{}'", domain);

    if domain.is_empty() {
        error!("Domain is empty");
        if is_htmx_request(&headers) {
            let entries = get_domains_from_config(&state);
            let template = LocalDomainsTableTemplate { entries };
            return super::render_template(template).into_response();
        }
        return Redirect::to("/edit/local_domains").into_response();
    }

    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_domains_from_config(&state);
                let template = LocalDomainsTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/local_domains").into_response();
        }
    };

    // Get existing domains or create new vec
    let mut domains = config.local_domains.domains.unwrap_or_default();

    // Check if domain already exists
    if domains.contains(&domain.to_string()) {
        error!("Domain '{}' already exists", domain);
        if is_htmx_request(&headers) {
            let entries = get_domains_from_config(&state);
            let template = LocalDomainsTableTemplate { entries };
            return super::render_template(template).into_response();
        }
        return Redirect::to("/edit/local_domains").into_response();
    }

    domains.push(domain.to_string());
    config.local_domains.domains = Some(domains);
    info!("Added local domain: {}", domain);

    match state.update_config(&config) {
        Ok(()) => {
            info!("Successfully saved local domain entry");
            if is_htmx_request(&headers) {
                let entries = get_domains_from_config(&state);
                let template = LocalDomainsTableTemplate { entries };
                super::render_template(template).into_response()
            } else {
                Redirect::to("/edit/local_domains").into_response()
            }
        }
        Err(e) => {
            error!("Failed to save local domains: {e}");
            if is_htmx_request(&headers) {
                let entries = get_domains_from_config(&state);
                let template = LocalDomainsTableTemplate { entries };
                super::render_template(template).into_response()
            } else {
                Redirect::to("/edit/local_domains").into_response()
            }
        }
    }
}

pub async fn update_local_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UpdateLocalDomainForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_domains_from_config(&state);
                let template = LocalDomainsTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/local_domains").into_response();
        }
    };

    let mut domains = config.local_domains.domains.unwrap_or_default();

    // Find and replace the old domain with the new one
    if let Some(pos) = domains.iter().position(|d| d == &form.old_domain) {
        domains[pos].clone_from(&form.new_domain);
        config.local_domains.domains = Some(domains);

        match state.update_config(&config) {
            Ok(()) => {
                info!(
                    "Updated local domain: {} -> {}",
                    form.old_domain, form.new_domain
                );
                if is_htmx_request(&headers) {
                    let entries = get_domains_from_config(&state);
                    let template = LocalDomainsTableTemplate { entries };
                    super::render_template(template).into_response()
                } else {
                    Redirect::to("/edit/local_domains").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after update: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_domains_from_config(&state);
                    let template = LocalDomainsTableTemplate { entries };
                    super::render_template(template).into_response()
                } else {
                    Redirect::to("/edit/local_domains").into_response()
                }
            }
        }
    } else {
        error!("Domain not found: {}", form.old_domain);
        if is_htmx_request(&headers) {
            let entries = get_domains_from_config(&state);
            let template = LocalDomainsTableTemplate { entries };
            super::render_template(template).into_response()
        } else {
            Redirect::to("/edit/local_domains").into_response()
        }
    }
}

pub async fn delete_local_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<DeleteLocalDomainForm>,
) -> impl IntoResponse {
    let mut config = match state.parse_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config: {e}");
            if is_htmx_request(&headers) {
                let entries = get_domains_from_config(&state);
                let template = LocalDomainsTableTemplate { entries };
                return super::render_template(template).into_response();
            }
            return Redirect::to("/edit/local_domains").into_response();
        }
    };

    let mut domains = config.local_domains.domains.unwrap_or_default();

    // Remove the specified domain
    if let Some(pos) = domains.iter().position(|d| d == &form.remove_domain) {
        domains.remove(pos);
        config.local_domains.domains = if domains.is_empty() {
            None
        } else {
            Some(domains)
        };

        match state.update_config(&config) {
            Ok(()) => {
                info!("Removed local domain: {}", form.remove_domain);
                if is_htmx_request(&headers) {
                    let entries = get_domains_from_config(&state);
                    let template = LocalDomainsTableTemplate { entries };
                    super::render_template(template).into_response()
                } else {
                    Redirect::to("/edit/local_domains").into_response()
                }
            }
            Err(e) => {
                error!("Failed to save config after deletion: {e}");
                if is_htmx_request(&headers) {
                    let entries = get_domains_from_config(&state);
                    let template = LocalDomainsTableTemplate { entries };
                    super::render_template(template).into_response()
                } else {
                    Redirect::to("/edit/local_domains").into_response()
                }
            }
        }
    } else {
        error!("Domain not found: {}", form.remove_domain);
        if is_htmx_request(&headers) {
            let entries = get_domains_from_config(&state);
            let template = LocalDomainsTableTemplate { entries };
            super::render_template(template).into_response()
        } else {
            Redirect::to("/edit/local_domains").into_response()
        }
    }
}
