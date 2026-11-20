use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    account_id: Option<i64>,
    #[serde(default)]
    size: Option<i64>,
    #[serde(default)]
    last_sort: Option<i64>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> Response {
    let size = q.size.unwrap_or(30).clamp(1, 30);
    let last_sort = q.last_sort.unwrap_or(9_999_999_999);
    let account_id = q.account_id.unwrap_or(0);
    let rows: Vec<(i64, String, String, i64, Option<String>, i64)> = sqlx::query_as(
        "SELECT account_id,email,name,status,latest_email_time,all_receive FROM account WHERE user_id=? AND is_del=0 AND (sort<? OR (sort=? AND account_id>?)) ORDER BY sort DESC, account_id ASC LIMIT ?"
    )
    .bind(user.user_id).bind(last_sort).bind(last_sort).bind(account_id).bind(size)
    .fetch_all(&state.pool).await.unwrap_or_default();
    let data = rows.into_iter().map(|r| json!({
        "accountId": r.0, "email": r.1, "name": r.2, "status": r.3,
        "latestEmailTime": r.4, "allReceive": r.5
    })).collect::<Vec<_>>();
    ok_value(Value::Array(data))
}

#[derive(Deserialize)]
pub struct AddRequest {
    pub email: String,
    #[serde(default)]
    pub token: Option<String>,
}

pub async fn add(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AddRequest>,
) -> Response {
    if !state.config.domain_allowed(&req.email) {
        return err(400, "notExistDomain");
    }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account WHERE email=? COLLATE NOCASE")
        .bind(&req.email).fetch_one(&state.pool).await.unwrap_or(0);
    if exists > 0 {
        return err(400, "isRegAccount");
    }
    let name = req.email.split('@').next().unwrap_or("").to_string();
    let result = sqlx::query("INSERT INTO account(email,name,user_id) VALUES(?,?,?)")
        .bind(&req.email).bind(&name).bind(user.user_id)
        .execute(&state.pool).await;
    match result {
        Ok(r) => ok_value(json!({"accountId": r.last_insert_rowid(), "email": req.email, "name": name})),
        Err(e) => { tracing::error!("add account failed: {e}"); err(500, "addAccountFailed") }
    }
}

#[derive(Deserialize)]
pub struct IdRequest {
    #[serde(alias = "accountId")]
    pub account_id: i64,
    #[serde(default)]
    pub name: Option<String>,
}

pub async fn set_name(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<IdRequest>,
) -> Response {
    if let Some(name) = &req.name {
        if name.len() > 30 {
            return err(400, "usernameLengthLimit");
        }
        sqlx::query("UPDATE account SET name=? WHERE account_id=? AND user_id=?")
            .bind(name).bind(req.account_id).bind(user.user_id)
            .execute(&state.pool).await.unwrap();
    }
    ok_value(json!(null))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(q): Query<IdRequest>,
) -> Response {
    sqlx::query("UPDATE account SET is_del=1 WHERE account_id=? AND user_id=?")
        .bind(q.account_id).bind(user.user_id)
        .execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

pub async fn set_all_receive(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<IdRequest>,
) -> Response {
    sqlx::query("UPDATE account SET all_receive=1-all_receive WHERE account_id=? AND user_id=?")
        .bind(req.account_id).bind(user.user_id)
        .execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

pub async fn set_as_top(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<IdRequest>,
) -> Response {
    sqlx::query("UPDATE account SET sort=(SELECT COALESCE(MAX(sort),0)+1 FROM account) WHERE account_id=? AND user_id=?")
        .bind(req.account_id).bind(user.user_id)
        .execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

fn err(code: u16, message: &str) -> Response {
    (axum::http::StatusCode::OK, Json(json!({"code":code,"message":message}))).into_response()
}
