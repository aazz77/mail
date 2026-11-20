use axum::extract::State;
use axum::response::Response;
use axum::Json;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

pub async fn query(State(state): State<Arc<AppState>>, _user: AuthUser) -> Response {
    ok_value(super::auth::current_setting(&state).await)
}

pub async fn website_config(State(state): State<Arc<AppState>>) -> Response {
    let setting = super::auth::current_setting(&state).await;
    let domains: Vec<String> = state.config.domains.iter().map(|d| format!("@{d}")).collect();
    // loginDomain == 1 hides the domain hint on the public login page.
    let login_domain = setting["login_domain"].as_i64().unwrap_or(0);
    let domain_list = if login_domain == 1 { Value::Array(vec![]) } else { json!(domains) };
    ok_value(json!({
        "register": setting["register"], "title": setting["title"],
        "manyEmail": setting["many_email"], "addEmail": setting["add_email"],
        "autoRefresh": setting["auto_refresh"], "addEmailVerify": setting["add_email_verify"],
        "registerVerify": setting["register_verify"], "send": setting["send"],
        "r2Domain": setting["r2_domain"], "siteKey": setting["site_key"],
        "background": setting["background"], "loginOpacity": setting["login_opacity"],
        "domainList": domain_list, "regKey": setting["reg_key"],
        "regVerifyOpen": false, "addVerifyOpen": false, "loginVerifyOpen": false,
        "noticeTitle": setting["notice_title"], "noticeContent": setting["notice_content"],
        "noticeType": setting["notice_type"], "noticeDuration": setting["notice_duration"],
        "noticePosition": setting["notice_position"], "noticeWidth": setting["notice_width"],
        "noticeOffset": setting["notice_offset"], "notice": setting["notice"],
        "loginDomain": setting["login_domain"], "minEmailPrefix": setting["min_email_prefix"],
        "projectLink": true,
        // OAuth providers: clientId + switch (0 = enabled)
        "linuxdoClientId": setting["linuxdo_client_id"], "linuxdoSwitch": setting["linuxdo_switch"],
        "githubClientId": setting["github_client_id"], "githubSwitch": setting["github_switch"],
        "googleClientId": setting["google_client_id"], "googleSwitch": setting["google_switch"]
    }))
}

pub async fn set(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<Value>) -> Response {
    let mut sets = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    for (key, value) in req.as_object().cloned().unwrap_or_default() {
        let column = match key.as_str() {
            "manyEmail" => "many_email", "addEmail" => "add_email", "autoRefresh" => "auto_refresh",
            "addEmailVerify" => "add_email_verify", "registerVerify" => "register_verify",
            "regVerifyCount" => "reg_verify_count", "addVerifyCount" => "add_verify_count",
            "r2Domain" => "r2_domain", "secretKey" => "secret_key", "siteKey" => "site_key",
            "regKey" => "reg_key", "background" => "background", "tgBotToken" => "tg_bot_token",
            "tgChatId" => "tg_chat_id", "tgBotStatus" => "tg_bot_status", "forwardEmail" => "forward_email",
            "forwardStatus" => "forward_status", "ruleEmail" => "rule_email", "ruleType" => "rule_type",
            "loginOpacity" => "login_opacity", "resendTokens" => "resend_tokens", "noticeTitle" => "notice_title",
            "noticeContent" => "notice_content", "noticeType" => "notice_type", "noticeDuration" => "notice_duration",
            "noticePosition" => "notice_position", "noticeOffset" => "notice_offset", "noticeWidth" => "notice_width",
            "notice" => "notice", "noRecipient" => "no_recipient", "loginDomain" => "login_domain",
            "bucket" => "bucket", "region" => "region", "endpoint" => "endpoint", "s3AccessKey" => "s3_access_key",
            "s3SecretKey" => "s3_secret_key", "forcePathStyle" => "force_path_style", "customDomain" => "custom_domain",
            "tgMsgFrom" => "tg_msg_from", "tgMsgTo" => "tg_msg_to", "tgMsgText" => "tg_msg_text",
            "minEmailPrefix" => "min_email_prefix", "emailPrefixFilter" => "email_prefix_filter",
            "blackSubject" => "black_subject", "blackContent" => "black_content", "blackFrom" => "black_from",
            "aiCode" => "ai_code", "syncDelete" => "sync_delete", "aiCodeFilter" => "ai_code_filter",
            "autoCleanDays" => "auto_clean_days", "autoCleanExclude" => "auto_clean_exclude",
            "webhookUrl" => "webhook_url", "webhookStatus" => "webhook_status", "webhookRetry" => "webhook_retry",
            "webhookSecret" => "webhook_secret", "linuxdoClientId" => "linuxdo_client_id",
            "linuxdoClientSecret" => "linuxdo_client_secret", "linuxdoSwitch" => "linuxdo_switch",
            "githubClientId" => "github_client_id", "githubClientSecret" => "github_client_secret",
            "githubSwitch" => "github_switch", "googleClientId" => "google_client_id",
            "googleClientSecret" => "google_client_secret", "googleSwitch" => "google_switch",
            _ => continue,
        };
        sets.push(format!("{column}=?"));
        values.push(value);
    }
    if !sets.is_empty() {
        let sql = format!("UPDATE setting SET {} WHERE id=1", sets.join(","));
        let mut query = sqlx::query(&sql);
        for value in values {
            query = bind_value(query, value);
        }
        let _ = query.execute(&state.pool).await;
    }
    ok_value(json!(null))
}

fn bind_value<'q>(query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>, value: Value) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    if let Some(v) = value.as_str() {
        query.bind(v.to_string())
    } else if let Some(v) = value.as_i64() {
        query.bind(v)
    } else if let Some(v) = value.as_f64() {
        query.bind(v)
    } else if let Some(v) = value.as_bool() {
        query.bind(if v {1i64} else {0i64})
    } else {
        query.bind(Option::<String>::None)
    }
}

pub async fn set_background(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<Value>) -> Response {
    let background = req.get("background").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if background.is_empty() {
        sqlx::query("UPDATE setting SET background='' WHERE id=1").execute(&state.pool).await.unwrap();
        return ok_value(json!(""));
    }
    if background.starts_with("http") {
        sqlx::query("UPDATE setting SET background=? WHERE id=1").bind(&background).execute(&state.pool).await.unwrap();
        return ok_value(json!(background));
    }
    // Data URI: `data:<mime>;base64,<payload>` — derive the extension from the
    // declared MIME type instead of assuming PNG.
    let (mime, payload) = background
        .split_once(',')
        .map(|(head, payload)| {
            let mime = head
                .strip_prefix("data:")
                .and_then(|s| s.split(';').next())
                .unwrap_or("image/png")
                .to_string();
            (mime, payload)
        })
        .unwrap_or(("image/png".to_string(), background.as_str()));
    let decoded = base64::engine::general_purpose::STANDARD.decode(payload).unwrap_or_default();
    let ext = match mime.to_lowercase().as_str() {
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/x-icon" | "image/vnd.microsoft.icon" => "ico",
        _ => "png",
    };
    let key = format!("static/background/{}.{}", hash(&decoded), ext);
    let _ = crate::storage::put_object(&state.config.storage_dir, &key, &decoded).await;
    sqlx::query("UPDATE setting SET background=? WHERE id=1").bind(&key).execute(&state.pool).await.unwrap();
    ok_value(json!(key))
}

pub async fn delete_background(State(state): State<Arc<AppState>>, _user: AuthUser) -> Response {
    sqlx::query("UPDATE setting SET background='' WHERE id=1").execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

pub async fn set_blacklist(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<Value>) -> Response {
    for key in ["blackSubject", "blackContent", "blackFrom"] {
        if let Some(v) = req.get(key).and_then(|v| v.as_str()) {
            let column = match key { "blackSubject" => "black_subject", "blackContent" => "black_content", _ => "black_from" };
            sqlx::query(&format!("UPDATE setting SET {column}=? WHERE id=1")).bind(v).execute(&state.pool).await.unwrap();
        }
    }
    ok_value(super::auth::current_setting(&state).await)
}

fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new(); hasher.update(bytes);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}
