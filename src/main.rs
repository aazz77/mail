mod config;
mod db;
mod error;
mod handlers;
mod models;
mod smtp_server;
mod storage;

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    services::{ServeDir, ServeFile},
};
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::Config;
use crate::models::AppState;

async fn log_errors(req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    if response.status().is_server_error() {
        tracing::error!("request failed: {}", response.status());
    }
    response
}

async fn api_error(code: u16, message: &str) -> Response {
    (
        StatusCode::OK,
        axum::Json(json!({ "code": code, "message": message })),
    )
        .into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cloud_mail_rust=info".parse()?))
        .init();

    let config = Arc::new(Config::from_env()?);
    let pool = db::init(&config.database_url).await?;
    sqlx::migrate!().run(&pool).await?;
    storage::init(&config.storage_dir).await?;
    handlers::tasks::spawn(pool.clone(), config.clone());

    let origins: Vec<axum::http::HeaderValue> = config
        .cors_origins
        .iter()
        .map(|origin| origin.parse())
        .collect::<Result<_, _>>()?;

    let state = Arc::new(AppState {
        pool,
        config: config.clone(),
    });

    let api = Router::new()
        .route("/login", post(handlers::auth::login))
        .route("/register", post(handlers::auth::register))
        .route("/logout", delete(handlers::auth::logout))
        .route("/my/loginUserInfo", get(handlers::auth::login_user_info))
        .route("/my/resetPassword", put(handlers::auth::reset_password))
        .route("/my/delete", delete(handlers::auth::delete_account))
        .route("/account/list", get(handlers::accounts::list))
        .route("/account/add", post(handlers::accounts::add))
        .route("/account/setName", put(handlers::accounts::set_name))
        .route("/account/delete", delete(handlers::accounts::delete))
        .route("/account/setAllReceive", put(handlers::accounts::set_all_receive))
        .route("/account/setAsTop", put(handlers::accounts::set_as_top))
        .route("/email/list", get(handlers::emails::list))
        .route("/email/latest", get(handlers::emails::latest))
        .route("/email/delete", delete(handlers::emails::delete))
        .route("/email/attList", get(handlers::emails::att_list))
        .route("/email/send", post(handlers::emails::send))
        .route("/email/read", put(handlers::emails::read))
        .route("/allEmail/list", get(handlers::emails::all_list))
        .route("/allEmail/delete", delete(handlers::emails::all_delete))
        .route("/allEmail/batchDelete", delete(handlers::emails::all_batch_delete))
        .route("/allEmail/latest", get(handlers::emails::all_latest))
        .route("/analysis/echarts", get(handlers::emails::analysis))
        .route("/setting/query", get(handlers::settings::query))
        .route("/setting/websiteConfig", get(handlers::settings::website_config))
        .route("/setting/set", put(handlers::settings::set))
        .route("/setting/setBackground", put(handlers::settings::set_background))
        .route("/setting/deleteBackground", delete(handlers::settings::delete_background))
        .route("/setting/setBlacklist", put(handlers::settings::set_blacklist))
        .route("/star/add", post(handlers::stars::add))
        .route("/star/list", get(handlers::stars::list))
        .route("/star/cancel", delete(handlers::stars::cancel))
        .route("/user/list", get(handlers::users::list))
        .route("/user/add", post(handlers::users::add))
        .route("/user/setPwd", put(handlers::users::set_password))
        .route("/user/setStatus", put(handlers::users::set_status))
        .route("/user/setType", put(handlers::users::set_type))
        .route("/user/delete", delete(handlers::users::delete))
        .route("/user/resetSendCount", put(handlers::users::reset_send_count))
        .route("/user/restore", put(handlers::users::restore))
        .route("/user/allAccount", get(handlers::users::all_accounts))
        .route("/user/deleteAccount", delete(handlers::users::delete_account))
        .route("/role/add", post(handlers::roles::add))
        .route("/role/set", put(handlers::roles::set))
        .route("/role/setDefault", put(handlers::roles::set_default))
        .route("/role/list", get(handlers::roles::list))
        .route("/role/tree", get(handlers::roles::tree))
        .route("/role/selectUse", get(handlers::roles::select_use))
        .route("/role/delete", delete(handlers::roles::delete))
        .route("/regKey/add", post(handlers::reg_keys::add))
        .route("/regKey/list", get(handlers::reg_keys::list))
        .route("/regKey/history", get(handlers::reg_keys::history))
        .route("/regKey/delete", delete(handlers::reg_keys::delete))
        .route("/regKey/clearNotUse", delete(handlers::reg_keys::clear_unused))
        .route("/oss/{*key}", get(handlers::storage::get_object))
        .route("/attachments/{*key}", get(handlers::storage::get_object))
        .route("/static/{*key}", get(handlers::storage::get_object))
        .route("/init/{secret}", get(handlers::init::init))
        .route("/webhooks", post(handlers::webhooks::resend))
        .layer(middleware::from_fn(log_errors))
        .layer(RequestBodyLimitLayer::new(64 * 1024 * 1024))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", api)
        .nest_service("/assets", ServeDir::new(&config.frontend_dir))
        .fallback_service(
            ServeDir::new(&config.frontend_dir)
                .not_found_service(ServeFile::new(format!("{}/index.html", config.frontend_dir))),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Start inbound SMTP server (optional — fails gracefully if port unavailable)
    let smtp_addr = format!("{}:{}", config.host, config.smtp_listen_port);
    match tokio::net::TcpListener::bind(&smtp_addr).await {
        Ok(smtp_listener) => {
            let smtp_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = smtp_server::run(smtp_listener, smtp_state).await {
                    tracing::error!("SMTP server error: {}", e);
                }
            });
        }
        Err(e) => {
            tracing::warn!(
                "Could not bind SMTP server on {}: {}. Inbound email will not be accepted.",
                smtp_addr, e
            );
        }
    }

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;
    tracing::info!("Cloud Mail Rust listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
