use askama::Template;
use axum::{
    Form,
    extract::State,
    response::{Html, IntoResponse, Redirect},
};
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
        std::fs::write(self.config_path.as_ref(), content)?;
        *self.config_content.write().unwrap() = content.to_string();
        Ok(())
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
