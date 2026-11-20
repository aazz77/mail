//! Telegram mini-app email preview (`/telegram/getEmail/:token`) plus the bot
//! notification helper used on inbound mail. Mirrors `telegram-service.js`.

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::models::AppState;
use crate::utils::{html_escape, jwt_sign, jwt_verify, proxy_sign};

#[derive(Serialize, Deserialize)]
struct MailClaim {
    #[serde(alias = "emailId")]
    email_id: i64,
    #[serde(default)]
    exp: i64,
}

/// Render an email as a standalone HTML page protected by a signed JWT token.
pub async fn get_email(
    Path(token): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let claim: Option<MailClaim> = jwt_verify(&token, &state.config.jwt_secret);
    let content = match claim {
        None => text_template("Access denied"),
        Some(claim) => {
            let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT content,text FROM email WHERE email_id=?",
            )
            .bind(claim.email_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
            match row {
                Some((Some(html), _)) if !html.trim().is_empty() => {
                    html_template(&rewrite_images(&html, &state.config.jwt_secret))
                }
                Some((_, Some(text))) => text_template(&text),
                _ => text_template("The email does not exist"),
            }
        }
    };
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, "public, max-age=3600, immutable".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; \
                 script-src 'unsafe-inline'; connect-src 'none'; object-src 'none'; \
                 base-uri 'none'; form-action 'none'; frame-src 'none'"
                    .to_string(),
            ),
        ],
        content,
    )
        .into_response()
}

/// Generate the signed JWT used in the Telegram "View" button URL.
pub fn mail_token(email_id: i64, secret: &str) -> String {
    jwt_sign(&json!({"emailId": email_id}), secret, 0i64).unwrap_or_default()
}

/// Rewrite external image URLs in HTML to the signed `/proxy?url=` endpoint so
/// the reader's IP is not exposed. This is a lightweight regex-based version of
/// the original DOM rewriter.
fn rewrite_images(html: &str, secret: &str) -> String {
    let re = match regex::Regex::new(r#"(?i)(src|data-src|poster|background)\s*=\s*(["'])(.*?)\2"#) {
        Ok(r) => r,
        Err(_) => return html.to_string(),
    };
    let exp = (chrono::Utc::now().timestamp() + 3600).to_string();
    re.replace_all(html, |caps: &regex::Captures| {
        let attr = &caps[1];
        let quote = &caps[2];
        let url = &caps[3];
        let lower = url.to_lowercase();
        if lower.starts_with("data:") || lower.starts_with("cid:") || lower.starts_with("blob:")
            || lower.starts_with("/") || lower.contains("/proxy?url=")
        {
            return caps[0].to_string();
        }
        if !lower.starts_with("http://") && !lower.starts_with("https://") {
            return caps[0].to_string();
        }
        let sig = proxy_sign(url, &exp, secret);
        format!(
            "{}={}/proxy?url={}&exp={}&sig={}{}",
            attr,
            quote,
            urlencoding_light(url),
            exp,
            sig,
            quote
        )
    })
    .to_string()
}

/// Minimal percent-encoding for URL query values (matches encodeURIComponent
/// closely enough for image URLs: keep unreserved and common path chars).
fn urlencoding_light(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Send an inbound email notification to the configured Telegram bots.
pub async fn send_to_bot(state: &Arc<AppState>, email_id: i64, code: &str, subject: &str, from: &str) {
    let setting = super::auth::current_setting(state).await;
    if setting.get("tg_bot_status").and_then(|v| v.as_i64()).unwrap_or(1) != 0 {
        return;
    }
    let token = sval(&setting, "tg_bot_token");
    let chat_ids = sval(&setting, "tg_chat_id");
    if token.is_empty() || chat_ids.is_empty() {
        return;
    }
    let custom_domain = sval(&setting, "custom_domain");
    let web_url = if custom_domain.is_empty() {
        "https://www.cloudflare.com/404".to_string()
    } else {
        let domain = custom_domain
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        format!(
            "https://{}/api/telegram/getEmail/{}",
            domain,
            mail_token(email_id, &state.config.jwt_secret)
        )
    };
    let mut keyboard = json!([[{"text": "View", "web_app": {"url": web_url}}]]);
    if !code.is_empty() {
        keyboard.as_array_mut().unwrap().push(json!([
            {"text": code, "copy_text": {"text": code}}
        ]));
    }
    let text = format!(
        "📧 {}\nfrom: {}\n{}",
        html_escape(subject),
        html_escape(from),
        if code.is_empty() { String::new() } else { format!("code: {}", code) }
    );

    let client = reqwest::Client::new();
    for chat_id in chat_ids.split(',') {
        let chat_id = chat_id.trim();
        if chat_id.is_empty() {
            continue;
        }
        let body = json!({
            "chat_id": chat_id,
            "parse_mode": "HTML",
            "text": text,
            "reply_markup": {"inline_keyboard": keyboard}
        });
        if let Err(e) = client
            .post(format!("https://api.telegram.org/bot{}/sendMessage", token))
            .json(&body)
            .send()
            .await
        {
            tracing::warn!("telegram forward failed: {}", e);
        }
    }
}

fn sval(setting: &serde_json::Value, key: &str) -> String {
    setting.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn text_template(text: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>\
         <meta name='viewport' content='width=device-width, initial-scale=1.0'>\
         <style>html,body{{margin:0;padding:0;background:#FFF}}body{{box-sizing:border-box;\
         padding:10px;width:100%;height:100%;overflow:auto}}span{{font-family:inherit;\
         white-space:pre-wrap;word-break:break-word}}</style></head>\
         <body><span>{}</span></body></html>",
        html_escape(text)
    )
}

fn html_template(html: &str) -> String {
    // JSON-encode the HTML string and escape `<` so it cannot break out of the
    // <script> block, matching the original emailHtmlTemplate safety measure.
    let encoded = serde_json::to_string(html).unwrap_or_default().replace('<', "\\u003C");
    format!(
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>\
         <meta name='viewport' content='width=device-width, initial-scale=1.0'>\
         <style>*{{box-sizing:border-box;margin:0}}img{{max-width:100%!important;height:auto}}</style>\
         </head><body><div id='container' style='padding:10px'></div><script>\
         var html={};var c=document.getElementById('container');\
         c.attachShadow({{mode:'open'}}).innerHTML=html;\
         </script></body></html>",
        encoded
    )
}
