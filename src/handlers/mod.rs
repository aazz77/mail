pub mod accounts;
pub mod auth;
pub mod emails;
pub mod init;
pub mod oauth;
pub mod proxy;
pub mod public_api;
pub mod reg_keys;
pub mod roles;
pub mod settings;
pub mod stars;
pub mod storage;
pub mod tasks;
pub mod telegram;
pub mod users;
pub mod webhooks;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::header::AUTHORIZATION;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::json;

use crate::models::AppState;

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub user_id: i64,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i64,
    pub token: String,
}

// ── Public paths (no auth required) ──────────────────────────────────────────
const EXCLUDE_PATHS: &[&str] = &[
    "/login",
    "/register",
    "/oss",
    "/setting/websiteConfig",
    "/webhooks",
    "/init",
    "/public",
    "/telegram",
    "/oauth",
];

// ── Paths that require a specific permission ─────────────────────────────────
const REQUIRE_PERMS: &[&str] = &[
    "/email/send",
    "/email/delete",
    "/account/list",
    "/account/delete",
    "/account/add",
    "/my/delete",
    "/analysis/echarts",
    "/role/add",
    "/role/list",
    "/role/delete",
    "/role/tree",
    "/role/set",
    "/role/setDefault",
    "/allEmail/list",
    "/allEmail/delete",
    "/allEmail/batchDelete",
    "/allEmail/latest",
    "/setting/setBackground",
    "/setting/deleteBackground",
    "/setting/set",
    "/setting/query",
    "/setting/setBlacklist",
    "/user/delete",
    "/user/setPwd",
    "/user/setStatus",
    "/user/setType",
    "/user/list",
    "/user/restore",
    "/user/resetSendCount",
    "/user/add",
    "/user/deleteAccount",
    "/user/allAccount",
    "/regKey/add",
    "/regKey/list",
    "/regKey/delete",
    "/regKey/clearNotUse",
    "/regKey/history",
];

// ── Permission key → allowed route prefixes ──────────────────────────────────
const PERM_PATHS: &[(&str, &[&str])] = &[
    ("email:delete", &["/email/delete"]),
    ("email:send", &["/email/send"]),
    ("account:add", &["/account/add"]),
    ("account:query", &["/account/list"]),
    ("account:delete", &["/account/delete"]),
    ("my:delete", &["/my/delete"]),
    ("role:add", &["/role/add"]),
    ("role:set", &["/role/set", "/role/setDefault"]),
    ("role:query", &["/role/list", "/role/tree"]),
    ("role:delete", &["/role/delete"]),
    ("user:query", &["/user/list", "/user/allAccount"]),
    ("user:add", &["/user/add"]),
    ("user:reset-send", &["/user/resetSendCount"]),
    ("user:set-pwd", &["/user/setPwd"]),
    ("user:set-status", &["/user/setStatus", "/user/restore"]),
    ("user:set-type", &["/user/setType"]),
    ("user:delete", &["/user/delete", "/user/deleteAccount"]),
    ("all-email:query", &["/allEmail/list", "/allEmail/latest"]),
    ("all-email:delete", &["/allEmail/delete", "/allEmail/batchDelete"]),
    ("setting:query", &["/setting/query"]),
    (
        "setting:set",
        &[
            "/setting/set",
            "/setting/setBackground",
            "/setting/deleteBackground",
            "/setting/setBlacklist",
        ],
    ),
    ("analysis:query", &["/analysis/echarts"]),
    ("reg-key:add", &["/regKey/add"]),
    ("reg-key:query", &["/regKey/list", "/regKey/history"]),
    ("reg-key:delete", &["/regKey/delete", "/regKey/clearNotUse"]),
];

impl FromRequestParts<std::sync::Arc<AppState>> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &std::sync::Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if token.is_empty() {
            return Err(unauthorized("authExpired"));
        }
        let mut validation = Validation::default();
        validation.required_spec_claims.remove("exp");
        validation.validate_exp = false;
        let data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| unauthorized("authExpired"))?;
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_session WHERE token = ? AND user_id = ?")
            .bind(&data.claims.token)
            .bind(data.claims.user_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| unauthorized("authExpired"))?;
        if exists == 0 {
            return Err(unauthorized("authExpired"));
        }

        let auth_user = AuthUser {
            user_id: data.claims.user_id,
            token: data.claims.token,
        };

        // Enforce path-level permissions
        if let Err(resp) = check_permission(state, &auth_user, parts).await {
            return Err(resp);
        }

        Ok(auth_user)
    }
}

async fn check_permission(
    state: &std::sync::Arc<AppState>,
    auth_user: &AuthUser,
    parts: &Parts,
) -> Result<(), Response> {
    let raw_path = parts.uri.path();
    let path = raw_path.strip_prefix("/api").unwrap_or(raw_path);

    // Public paths skip permission check
    if EXCLUDE_PATHS.iter().any(|p| path.starts_with(p)) {
        return Ok(());
    }

    // Paths not in REQUIRE_PERMS are accessible to any authenticated user
    if !REQUIRE_PERMS.iter().any(|p| path.starts_with(p)) {
        return Ok(());
    }

    // Admin bypasses all permission checks
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM user WHERE user_id = ?")
        .bind(auth_user.user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if email
        .map(|e| e.eq_ignore_ascii_case(&state.config.admin))
        .unwrap_or(false)
    {
        return Ok(());
    }

    // Get user's permission keys
    let perm_keys: Vec<String> = sqlx::query_scalar(
        "SELECT p.perm_key FROM role_perm rp \
         JOIN perm p ON p.perm_id = rp.perm_id \
         JOIN user u ON u.type = rp.role_id \
         WHERE u.user_id = ? AND p.perm_key IS NOT NULL",
    )
    .bind(auth_user.user_id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Map permission keys to allowed paths
    let mut allowed: Vec<&str> = Vec::new();
    for key in &perm_keys {
        for (perm_key, paths) in PERM_PATHS {
            if perm_key == key {
                allowed.extend(paths.iter().copied());
            }
        }
    }

    if allowed.iter().any(|p| path.starts_with(p)) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

pub fn unauthorized(message: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        axum::Json(json!({ "code": 401, "message": message })),
    )
        .into_response()
}

pub fn forbidden() -> Response {
    (
        axum::http::StatusCode::OK,
        axum::Json(json!({ "code": 403, "message": "unauthorized" })),
    )
        .into_response()
}

pub fn err(code: u16, message: &str) -> Response {
    (
        axum::http::StatusCode::OK,
        axum::Json(json!({ "code": code, "message": message })),
    )
        .into_response()
}

pub fn ok<T: serde::Serialize>(data: T) -> Response {
    let value = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
    (
        axum::http::StatusCode::OK,
        axum::Json(json!({ "code": 200, "message": "success", "data": value })),
    )
        .into_response()
}

pub fn ok_value(data: serde_json::Value) -> Response {
    (
        axum::http::StatusCode::OK,
        axum::Json(json!({ "code": 200, "message": "success", "data": data })),
    )
        .into_response()
}
