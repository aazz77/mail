//! OAuth sign-in via LinuxDo / GitHub / Google plus account binding.
//! Mirrors the original `oauth-service.js`: exchange the code for an access
//! token, fetch the provider profile, upsert the `oauth` row and, when the
//! profile is already bound to a local user, issue a JWT session.

use axum::extract::State;
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::{err, ok_value};
use crate::models::AppState;
use crate::utils::{jwt_sign, valid_email};

#[derive(Deserialize)]
pub struct LoginParams {
    #[serde(default)] pub code: String,
    #[serde(default, alias = "redirectUri")] pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct BindParams {
    #[serde(default)] pub email: String,
    #[serde(default, alias = "oauthUserId")] pub oauth_user_id: String,
    #[serde(default)] pub code: String,
}

// ── Provider sign-in endpoints ───────────────────────────────────────────────

pub async fn linux_do_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginParams>,
) -> Response {
    let setting = super::auth::current_setting(&state).await;
    if !switch_open(&setting, "linuxdo_switch") {
        return err(400, "oauthDisabled");
    }

    let mut form = Vec::new();
    form.push(("client_id", sval(&setting, "linuxdo_client_id")));
    form.push(("client_secret", sval(&setting, "linuxdo_client_secret")));
    form.push(("code", req.code.clone()));
    form.push(("redirect_uri", req.redirect_uri.clone()));
    form.push(("grant_type", "authorization_code".to_string()));

    let client = reqwest::Client::new();
    let token_res = client
        .post("https://connect.linux.do/oauth2/token")
        .form(&form)
        .send()
        .await;
    let token_res = match token_res {
        Ok(r) => r,
        Err(e) => return err(400, &e.to_string()),
    };
    if !token_res.status().is_success() {
        return err(400, token_res.status().as_str());
    }
    let token: Value = match token_res.json().await {
        Ok(v) => v,
        Err(e) => return err(400, &e.to_string()),
    };
    let access = token.get("access_token").and_then(|v| v.as_str()).unwrap_or("");

    let user_res = client
        .get("https://connect.linux.do/api/user")
        .bearer_auth(access)
        .send()
        .await;
    let user_res = match user_res {
        Ok(r) => r,
        Err(e) => return err(400, &e.to_string()),
    };
    if !user_res.status().is_success() {
        return err(400, user_res.status().as_str());
    }
    let mut info: Value = match user_res.json().await {
        Ok(v) => v,
        Err(e) => return err(400, &e.to_string()),
    };
    let oauth_uid = info.get("id").map(|v| v.to_string()).unwrap_or_default();
    info["oauth_user_id"] = json!(oauth_uid);
    info["active"] = json!(to_bool_int(info.get("active")) ^ 1);
    info["silenced"] = json!(to_bool_int(info.get("silenced")) ^ 1);
    info["trust_level"] = info.get("trust_level").cloned().unwrap_or(json!(null));
    info["avatar"] = info.get("avatar_url").cloned().unwrap_or(json!(null));
    info["platform"] = json!("linuxdo");
    finalize(&state, info, &oauth_uid).await
}

pub async fn github_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginParams>,
) -> Response {
    let setting = super::auth::current_setting(&state).await;
    if !switch_open(&setting, "github_switch") {
        return err(400, "oauthDisabled");
    }
    let client = reqwest::Client::new();
    let token_res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&json!({
            "client_id": sval(&setting, "github_client_id"),
            "client_secret": sval(&setting, "github_client_secret"),
            "code": req.code,
            "redirect_uri": req.redirect_uri,
        }))
        .send()
        .await;
    let token_res = match token_res {
        Ok(r) => r,
        Err(e) => return err(400, &e.to_string()),
    };
    let token: Value = match token_res.json().await {
        Ok(v) => v,
        Err(e) => return err(400, &e.to_string()),
    };
    if let Some(e) = token.get("error") {
        return err(400, token.get("error_description").and_then(|v| v.as_str()).unwrap_or(e.as_str().unwrap_or("oauthError")));
    }
    let access = token.get("access_token").and_then(|v| v.as_str()).unwrap_or("");

    let user_res = client
        .get("https://api.github.com/user")
        .bearer_auth(access)
        .header("User-Agent", "cloud-mail")
        .send()
        .await;
    let user_res = match user_res {
        Ok(r) => r,
        Err(e) => return err(400, &e.to_string()),
    };
    if !user_res.status().is_success() {
        return err(400, user_res.status().as_str());
    }
    let mut info: Value = match user_res.json().await {
        Ok(v) => v,
        Err(e) => return err(400, &e.to_string()),
    };
    let oauth_uid = info.get("id").map(|v| v.to_string()).unwrap_or_default();
    info["oauth_user_id"] = json!(oauth_uid);
    info["username"] = info.get("login").cloned().unwrap_or(json!(null));
    info["avatar"] = info.get("avatar_url").cloned().unwrap_or(json!(null));
    info["platform"] = json!("github");
    finalize(&state, info, &oauth_uid).await
}

pub async fn google_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginParams>,
) -> Response {
    let setting = super::auth::current_setting(&state).await;
    if !switch_open(&setting, "google_switch") {
        return err(400, "oauthDisabled");
    }
    let mut form = Vec::new();
    form.push(("client_id", sval(&setting, "google_client_id")));
    form.push(("client_secret", sval(&setting, "google_client_secret")));
    form.push(("code", req.code.clone()));
    form.push(("redirect_uri", req.redirect_uri.clone()));
    form.push(("grant_type", "authorization_code".to_string()));

    let client = reqwest::Client::new();
    let token_res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&form)
        .send()
        .await;
    let token_res = match token_res {
        Ok(r) => r,
        Err(e) => return err(400, &e.to_string()),
    };
    if !token_res.status().is_success() {
        return err(400, token_res.status().as_str());
    }
    let token: Value = match token_res.json().await {
        Ok(v) => v,
        Err(e) => return err(400, &e.to_string()),
    };
    let access = token.get("access_token").and_then(|v| v.as_str()).unwrap_or("");

    let user_res = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access)
        .send()
        .await;
    let user_res = match user_res {
        Ok(r) => r,
        Err(e) => return err(400, &e.to_string()),
    };
    if !user_res.status().is_success() {
        return err(400, user_res.status().as_str());
    }
    let mut info: Value = match user_res.json().await {
        Ok(v) => v,
        Err(e) => return err(400, &e.to_string()),
    };
    let oauth_uid = info.get("sub").map(|v| v.to_string()).unwrap_or_default();
    info["oauth_user_id"] = json!(oauth_uid);
    info["username"] = info.get("email").cloned().unwrap_or(json!(null));
    info["avatar"] = info.get("picture").cloned().unwrap_or(json!(null));
    info["platform"] = json!("google");
    finalize(&state, info, &oauth_uid).await
}

// ── Binding ──────────────────────────────────────────────────────────────────

pub async fn bind_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BindParams>,
) -> Response {
    if !valid_email(&req.email) {
        return err(400, "notEmail");
    }
    if !state.config.domain_allowed(&req.email) {
        return err(400, "notEmailDomain");
    }

    // oauth row must exist and must not be bound yet
    let bound: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM oauth WHERE oauth_user_id=? ORDER BY oauth_id DESC LIMIT 1",
    )
    .bind(&req.oauth_user_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);
    match bound {
        None => return err(400, "notExistOauthUser"),
        Some(uid) if uid != 0 => return err(400, "oauthAlreadyBind"),
        _ => {}
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user WHERE email=? COLLATE NOCASE")
        .bind(&req.email)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(1);
    if exists > 0 {
        return err(400, "isRegAccount");
    }

    // Accept any valid registration code when regKey is enabled, otherwise use
    // the default role. Reuse the same role resolution as normal registration.
    let role_id = crate::handlers::auth::resolve_role_for_register(&state, Some(&req.code)).await;
    let role_id = match role_id {
        Ok(v) => v,
        Err(msg) => return err(400, &msg),
    };
    let (salt, hash) = crate::handlers::auth::hash_password(&random_pwd());
    let result = sqlx::query(
        "INSERT INTO user(email,type,password,salt,status,reg_key_id) VALUES(?,?,?,?,0,0)",
    )
    .bind(&req.email)
    .bind(role_id)
    .bind(&hash)
    .bind(&salt)
    .execute(&state.pool)
    .await;
    let user_id = match result {
        Ok(r) => r.last_insert_rowid(),
        Err(e) => {
            tracing::error!("oauth bind register failed: {e}");
            return err(500, "registerFailed");
        }
    };
    let name = req.email.split('@').next().unwrap_or("").to_string();
    let _ = sqlx::query("INSERT INTO account(email,name,user_id) VALUES(?,?,?)")
        .bind(&req.email)
        .bind(&name)
        .bind(user_id)
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("UPDATE oauth SET user_id=? WHERE oauth_user_id=?")
        .bind(user_id)
        .bind(&req.oauth_user_id)
        .execute(&state.pool)
        .await;

    let login_info = info_for_user(&state, user_id).await;
    ok_value(login_info)
}

// ── helpers ──────────────────────────────────────────────────────────────────

async fn finalize(state: &Arc<AppState>, info: Value, oauth_uid: &str) -> Response {
    // upsert oauth row
    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth WHERE oauth_user_id=?",
    )
    .bind(oauth_uid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);
    let platform = info.get("platform").and_then(|v| v.as_str()).unwrap_or("");
    let username = str_val(&info, "username");
    let name = str_val(&info, "name");
    let avatar = str_val(&info, "avatar");
    let active = info.get("active").and_then(|v| v.as_i64()).unwrap_or(0);
    let trust = info.get("trust_level").and_then(|v| v.as_i64()).unwrap_or(0);
    let silenced = info.get("silenced").and_then(|v| v.as_i64()).unwrap_or(0);
    if existing == 0 {
        let _ = sqlx::query(
            "INSERT INTO oauth(oauth_user_id,username,name,avatar,active,trust_level,silenced,platform,user_id) \
             VALUES(?,?,?,?,?,?,?,?,0)",
        )
        .bind(oauth_uid).bind(&username).bind(&name).bind(&avatar)
        .bind(active).bind(trust).bind(silenced).bind(platform)
        .execute(&state.pool).await;
    } else {
        let _ = sqlx::query(
            "UPDATE oauth SET username=?,name=?,avatar=?,active=?,trust_level=?,silenced=?,platform=? \
             WHERE oauth_user_id=?",
        )
        .bind(&username).bind(&name).bind(&avatar)
        .bind(active).bind(trust).bind(silenced).bind(platform)
        .bind(oauth_uid)
        .execute(&state.pool).await;
    }

    let oauth_row: Value = sqlx::query(
        "SELECT oauth_id,oauth_user_id,username,name,avatar,active,trust_level,silenced,platform,user_id \
         FROM oauth WHERE oauth_user_id=? ORDER BY oauth_id DESC LIMIT 1",
    )
    .bind(oauth_uid)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(row_to_json)
    .unwrap_or(json!({}));

    let user_id: Option<i64> = sqlx::query_scalar(
        "SELECT user_id FROM oauth WHERE oauth_user_id=? ORDER BY oauth_id DESC LIMIT 1",
    )
    .bind(oauth_uid)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let token = match user_id {
        Some(uid) if uid > 0 => issue_token(state, uid).await,
        _ => Value::Null,
    };
    ok_value(json!({ "userInfo": oauth_row, "token": token }))
}

async fn info_for_user(state: &Arc<AppState>, user_id: i64) -> Value {
    let oauth_row = sqlx::query(
        "SELECT oauth_id,oauth_user_id,username,name,avatar,active,trust_level,silenced,platform,user_id \
         FROM oauth WHERE user_id=? ORDER BY oauth_id DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(row_to_json)
    .unwrap_or(json!({}));
    json!({ "userInfo": oauth_row, "token": issue_token(state, user_id).await })
}

async fn issue_token(state: &Arc<AppState>, user_id: i64) -> Value {
    let token = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query("INSERT INTO auth_session(token,user_id) VALUES(?,?)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.pool)
        .await;
    crate::handlers::auth::trim_sessions(&state.pool, user_id).await;
    match jwt_sign(
        &json!({"user_id": user_id, "token": token}),
        &state.config.jwt_secret,
        0,
    ) {
        Ok(jwt) => json!(jwt),
        Err(_) => Value::Null,
    }
}

fn row_to_json(row: sqlx::sqlite::SqliteRow) -> Value {
    use sqlx::Row;
    json!({
        "oauthUserId": row.get::<String, _>("oauth_user_id"),
        "username": row.get::<Option<String>, _>("username"),
        "name": row.get::<Option<String>, _>("name"),
        "avatar": row.get::<Option<String>, _>("avatar"),
        "active": row.get::<Option<i64>, _>("active"),
        "trustLevel": row.get::<Option<i64>, _>("trust_level"),
        "silenced": row.get::<Option<i64>, _>("silenced"),
        "platform": row.get::<Option<String>, _>("platform"),
        "userId": row.get::<i64, _>("user_id")
    })
}

pub async fn clear_no_bind_users(pool: &sqlx::SqlitePool) {
    let _ = sqlx::query("DELETE FROM oauth WHERE user_id=0")
        .execute(pool)
        .await;
}

fn switch_open(setting: &Value, key: &str) -> bool {
    setting.get(key).and_then(|v| v.as_i64()).unwrap_or(1) == 0
}

fn sval(setting: &Value, key: &str) -> String {
    setting.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn str_val(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn to_bool_int(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Bool(b)) => {
            if *b { 1 } else { 0 }
        }
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => {
            if s == "true" || s == "1" { 1 } else { 0 }
        }
        _ => 0,
    }
}

fn random_pwd() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}
