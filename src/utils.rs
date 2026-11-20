//! Shared helpers for JWT (HS256, compatible with the original Worker),
//! HMAC signing used by the image proxy, and small validation routines.

use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generate an HS256 JWT. `expires_in_secs == 0` omits the `exp` claim, matching
/// the original `jwtUtils.generateToken` behaviour.
pub fn jwt_sign<T: Serialize>(
    payload: &T,
    secret: &str,
    expires_in_secs: i64,
) -> Result<String, String> {
    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some("JWT".to_string());
    let token = if expires_in_secs > 0 {
        let now = chrono::Utc::now().timestamp();
        let mut value = serde_json::to_value(payload).map_err(|e| e.to_string())?;
        let obj = value.as_object_mut().ok_or("payload not object")?;
        obj.insert("iat".into(), serde_json::json!(now));
        obj.insert("exp".into(), serde_json::json!(now + expires_in_secs));
        encode(
            &header,
            &serde_json::from_value::<serde_json::Value>(value).map_err(|e| e.to_string())?,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    } else {
        encode(
            &header,
            payload,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
    };
    token.map_err(|e| e.to_string())
}

/// Verify an HS256 JWT and return the decoded claims.
pub fn jwt_verify<T: DeserializeOwned>(token: &str, secret: &str) -> Option<T> {
    let mut validation = Validation::new(Algorithm::HS256);
    // The original tokens may not carry `exp`; verify it only when present.
    validation.validate_exp = false;
    validation.required_spec_claims.remove("exp");
    decode::<T>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|data| data.claims)
}

/// Derive the image-proxy signing key from the JWT secret (matches the
/// original `HMAC(jwt_secret, "cloud-mail/image-proxy/v1")`).
fn proxy_key(secret: &str) -> Vec<u8> {
    let mut root = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    root.update(b"cloud-mail/image-proxy/v1");
    root.finalize().into_bytes().to_vec()
}

/// Produce a base64url HMAC-SHA256 signature over `input` for the image proxy.
pub fn proxy_sign(url: &str, exp: &str, secret: &str) -> String {
    let input = serde_json::json!([url, exp]).to_string();
    let mut mac = HmacSha256::new_from_slice(&proxy_key(secret)).expect("hmac key");
    mac.update(input.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Constant-time-ish verification of the image-proxy signature.
pub fn proxy_verify(url: &str, exp: &str, sig: &str, secret: &str) -> bool {
    let expected = proxy_sign(url, exp, secret);
    expected.len() == sig.len()
        && expected
            .as_bytes()
            .iter()
            .zip(sig.as_bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Basic email syntax check (single @, non-empty local part, dotted domain).
pub fn valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && parts[1].contains('.')
        && !parts[1].starts_with('.')
        && !parts[1].ends_with('.')
}

pub fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Extract the client IP from common proxy headers, falling back to the
/// socket address supplied by axum.
pub fn client_ip(headers: &axum::http::HeaderMap, fallback: &str) -> String {
    for name in ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let ip = value.split(',').next().unwrap_or("").trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    fallback.to_string()
}
