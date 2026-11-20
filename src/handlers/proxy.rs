//! Signed image proxy (`/proxy?url=&exp=&sig=`). Validates the HMAC signature,
//! blocks private/literal IP targets, fetches the remote image and returns only
//! allowed image media types — prevents leaking the reader's IP to senders.

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::sync::Arc;

use crate::models::AppState;
use crate::utils::proxy_verify;

#[derive(Deserialize)]
pub struct ProxyQuery {
    #[serde(default)] pub url: String,
    #[serde(default)] pub exp: String,
    #[serde(default)] pub sig: String,
}

const ALLOWED_TYPES: &[&str] = &[
    "image/avif", "image/bmp", "image/gif", "image/jpeg", "image/pjpeg",
    "image/png", "image/webp", "image/apng", "image/x-icon",
    "image/vnd.microsoft.icon",
];

pub async fn fetch_image(
    Query(q): Query<ProxyQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // exp must be a positive unix timestamp in the future
    let exp = match q.exp.parse::<i64>() {
        Ok(v) if v > 0 => v,
        _ => return StatusCode::FORBIDDEN.into_response(),
    };
    if exp <= chrono::Utc::now().timestamp() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if q.url.is_empty() || !proxy_verify(&q.url, &q.exp, &q.sig, &state.config.jwt_secret) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Validate target: http(s) only, public hostname, no userinfo
    let parsed = match reqwest::Url::parse(&q.url) {
        Ok(u) => u,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !safe_target(&parsed) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let res = match client
        .get(parsed.clone())
        .header("X-Real-IP", "192.0.2.1")
        .header("CF-Connecting-IP", "192.0.2.1")
        .header("Referer", "")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if !res.status().is_success() {
        return StatusCode::BAD_GATEWAY.into_response();
    }

    let mut content_type = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if content_type.is_empty() || content_type == "application/octet-stream" {
        if let Some(ext) = parsed.path().rsplit('.').next() {
            content_type = match ext.to_lowercase().as_str() {
                "jpg" | "jpeg" | "jpe" | "jfif" => "image/jpeg".to_string(),
                "png" => "image/png".to_string(),
                "gif" => "image/gif".to_string(),
                "webp" => "image/webp".to_string(),
                "avif" => "image/avif".to_string(),
                "bmp" => "image/bmp".to_string(),
                "ico" => "image/x-icon".to_string(),
                _ => content_type,
            };
        }
    }
    if !ALLOWED_TYPES.contains(&content_type.as_str()) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=3600".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::CONTENT_SECURITY_POLICY, "sandbox; default-src 'none'".to_string()),
            (header::REFERRER_POLICY, "no-referrer".to_string()),
        ],
        Body::from(bytes.to_vec()),
    )
        .into_response()
}

/// Reject credentials, non-http schemes, IP literals, localhost and internal
/// hostnames. DNS rebinding is not resolved here (matches the original).
fn safe_target(url: &reqwest::Url) -> bool {
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let host = match url.host_str() {
        Some(h) => h.trim_end_matches('.'),
        None => return false,
    };
    if !host.contains('.') || host.starts_with('[') {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    let lower = host.to_lowercase();
    if lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower == "localhost"
    {
        return false;
    }
    true
}
