//! Public API: admin token generation, cross-user email search and batch
//! user creation. Mirrors the original `public-service.js`.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::{err, ok_value};
use crate::models::AppState;
use crate::utils::{client_ip, valid_email};

const PUBLIC_KEY: &str = "public_key:";

/// Validate the `Authorization` header against the public token stored in KV.
/// Mirrors `security/security.js` for the `/public/*` route group.
async fn check_public_token(state: &Arc<AppState>, headers: &HeaderMap) -> Result<(), Response> {
    let expected = crate::kv::get(&state.pool, PUBLIC_KEY).await;
    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match expected {
        Some(token) if !token.is_empty() && token == provided => Ok(()),
        _ => Err(err(401, "publicTokenFail")),
    }
}

#[derive(Deserialize)]
pub struct TokenParams {
    #[serde(default)] pub email: String,
    #[serde(default)] pub password: String,
}

/// Verify the caller is the admin, then issue a UUID token stored in KV.
pub async fn gen_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TokenParams>,
) -> Response {
    if !req.email.eq_ignore_ascii_case(&state.config.admin) {
        return err(403, "notAdmin");
    }
    let row: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT password,salt,email,is_del FROM user WHERE email=? COLLATE NOCASE",
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);
    let (stored, salt, _email, is_del) = match row {
        Some(v) => v,
        None => return err(400, "notExistUser"),
    };
    if is_del == 1 {
        return err(400, "notExistUser");
    }
    if !crate::handlers::auth::verify_password(&req.password, &salt, &stored) {
        return err(400, "IncorrectPwd");
    }
    let token = uuid::Uuid::new_v4().to_string();
    crate::kv::put(&state.pool, PUBLIC_KEY, &token, 0).await;
    ok_value(json!({ "token": token }))
}

#[derive(Deserialize, Default)]
pub struct ListParams {
    #[serde(default, alias = "toEmail")] pub to_email: Option<String>,
    #[serde(default)] pub content: Option<String>,
    #[serde(default)] pub subject: Option<String>,
    #[serde(default, alias = "sendName")] pub send_name: Option<String>,
    #[serde(default, alias = "sendEmail")] pub send_email: Option<String>,
    #[serde(default, alias = "timeSort")] pub time_sort: Option<String>,
    #[serde(default)] pub num: Option<i64>,
    #[serde(default)] pub size: Option<i64>,
    #[serde(default)] pub r#type: Option<i64>,
    #[serde(default, alias = "isDel")] pub is_del: Option<i64>,
}

/// Public email search with case-insensitive LIKE filters.
pub async fn email_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ListParams>,
) -> Response {
    if let Err(resp) = check_public_token(&state, &headers).await {
        return resp;
    }
    let size = req.size.unwrap_or(20).clamp(1, 200);
    let page = req.num.unwrap_or(1).max(1);
    let offset = (page - 1) * size;

    let mut sql = String::from(
        "SELECT email_id,send_email,name,subject,to_email,to_name,type,create_time,content,text,is_del \
         FROM email WHERE 1=1",
    );
    // Keep text and numeric binds in exactly the order clauses are appended.
    enum Bind {
        Text(String),
        Num(i64),
    }
    let mut binds: Vec<Bind> = Vec::new();
    if let Some(v) = req.to_email.filter(|v| !v.is_empty()) {
        sql.push_str(" AND to_email COLLATE NOCASE LIKE ?");
        binds.push(Bind::Text(v));
    }
    if let Some(v) = req.send_email.filter(|v| !v.is_empty()) {
        sql.push_str(" AND send_email COLLATE NOCASE LIKE ?");
        binds.push(Bind::Text(v));
    }
    if let Some(v) = req.send_name.filter(|v| !v.is_empty()) {
        sql.push_str(" AND name COLLATE NOCASE LIKE ?");
        binds.push(Bind::Text(v));
    }
    if let Some(v) = req.subject.filter(|v| !v.is_empty()) {
        sql.push_str(" AND subject COLLATE NOCASE LIKE ?");
        binds.push(Bind::Text(v));
    }
    if let Some(v) = req.content.filter(|v| !v.is_empty()) {
        sql.push_str(" AND content COLLATE NOCASE LIKE ?");
        binds.push(Bind::Text(v));
    }
    if let Some(t) = req.r#type {
        sql.push_str(" AND type=?");
        binds.push(Bind::Num(t));
    }
    if let Some(d) = req.is_del {
        sql.push_str(" AND is_del=?");
        binds.push(Bind::Num(d));
    }
    sql.push_str(if req.time_sort.as_deref() == Some("asc") {
        " ORDER BY email_id ASC"
    } else {
        " ORDER BY email_id DESC"
    });
    sql.push_str(" LIMIT ? OFFSET ?");

    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = match b {
            Bind::Text(v) => q.bind(v.clone()),
            Bind::Num(n) => q.bind(*n),
        };
    }
    let rows = q.bind(size).bind(offset).fetch_all(&state.pool).await.unwrap_or_default();

    use sqlx::Row;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "emailId": r.get::<i64, _>("email_id"),
                "sendEmail": r.get::<Option<String>, _>("send_email"),
                "name": r.get::<Option<String>, _>("name"),
                "subject": r.get::<Option<String>, _>("subject"),
                "toEmail": r.get::<Option<String>, _>("to_email"),
                "toName": r.get::<Option<String>, _>("to_name"),
                "type": r.get::<i64, _>("type"),
                "createTime": r.get::<Option<String>, _>("create_time"),
                "content": r.get::<Option<String>, _>("content"),
                "text": r.get::<Option<String>, _>("text"),
                "isDel": r.get::<i64, _>("is_del"),
            })
        })
        .collect();
    ok_value(Value::Array(list))
}

#[derive(Deserialize)]
pub struct AddUserParams {
    pub list: Vec<AddUserRow>,
}

#[derive(Deserialize)]
pub struct AddUserRow {
    pub email: String,
    #[serde(default)] pub password: Option<String>,
    #[serde(default, alias = "roleName")] pub role_name: Option<String>,
}

/// Batch-create users + their default mailbox, restricted to configured domains.
pub async fn add_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddUserParams>,
) -> Response {
    if let Err(resp) = check_public_token(&state, &headers).await {
        return resp;
    }
    if req.list.is_empty() {
        return ok_value(json!(null));
    }
    let ip = client_ip(&axum::http::HeaderMap::new(), "127.0.0.1");
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let role_rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT role_id,name,is_default FROM role ORDER BY sort,role_id",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let default_role = role_rows
        .iter()
        .find(|r| r.2 == 1)
        .map(|r| r.0)
        .unwrap_or(1);

    for row in &req.list {
        if !valid_email(&row.email) {
            return err(400, "notEmail");
        }
        if !state.config.domain_allowed(&row.email) {
            return err(400, "notEmailDomain");
        }
        let role_id = row
            .role_name
            .as_ref()
            .and_then(|name| role_rows.iter().find(|r| &r.1 == name).map(|r| r.0))
            .unwrap_or(default_role);
        let password = row.password.clone().unwrap_or_else(random_pwd);
        let (salt, hash) = crate::handlers::auth::hash_password(&password);
        let name = row.email.split('@').next().unwrap_or("").to_string();
        let result = sqlx::query(
            "INSERT INTO user(email,password,salt,type,os,browser,active_ip,create_ip,device,active_time,create_time) \
             VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&row.email).bind(&hash).bind(&salt).bind(role_id)
        .bind("").bind("").bind(&ip).bind(&ip).bind("").bind(&now).bind(&now)
        .execute(&state.pool)
        .await;
        let user_id = match result {
            Ok(r) => r.last_insert_rowid(),
            Err(e) => {
                if e.to_string().to_uppercase().contains("UNIQUE") || e.to_string().contains("CONSTRAINT") {
                    return err(400, "emailExistDatabase");
                }
                return err(500, "addUserFailed");
            }
        };
        let _ = sqlx::query("INSERT INTO account(email,name,user_id) VALUES(?,?,?)")
            .bind(&row.email).bind(&name).bind(user_id)
            .execute(&state.pool)
            .await;
    }
    ok_value(json!(null))
}

fn random_pwd() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..8).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}
