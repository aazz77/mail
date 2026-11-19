use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

#[derive(Deserialize)]
pub struct AddRequest {
    pub code: String,
    pub roleId: i64,
    pub count: i64,
    pub expireTime: String,
}

pub async fn add(State(state): State<Arc<AppState>>, user: AuthUser, Json(req): Json<AddRequest>) -> Response {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reg_key WHERE code=? COLLATE NOCASE").bind(&req.code).fetch_one(&state.pool).await.unwrap_or(0);
    if exists > 0 { return err(400, "isExistRegKye"); }
    sqlx::query("INSERT INTO reg_key(code,count,role_id,user_id,expire_time) VALUES(?,?,?,?,?)")
        .bind(&req.code).bind(req.count).bind(req.roleId).bind(user.user_id).bind(&req.expireTime)
        .execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

pub async fn list(State(state): State<Arc<AppState>>, _user: AuthUser, Query(_q): Query<serde_json::Value>) -> Response {
    let rows: Vec<(i64,String,i64,i64,Option<String>)> = sqlx::query_as("SELECT rege_key_id,code,count,role_id,expire_time FROM reg_key ORDER BY rege_key_id DESC").fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(Value::Array(rows.into_iter().map(|r| json!({"regKeyId":r.0,"code":r.1,"count":r.2,"roleId":r.3,"expireTime":r.4})).collect()))
}

pub async fn history(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<serde_json::Value>) -> Response {
    let id = q.get("regKeyId").and_then(|v| v.as_i64()).unwrap_or(0);
    let rows: Vec<(i64,String)> = sqlx::query_as("SELECT user_id,email FROM user WHERE reg_key_id=? ORDER BY user_id DESC").bind(id).fetch_all(&state.pool).await.unwrap_or_default();
    let total = rows.len();
    ok_value(json!({"list": rows.into_iter().map(|r| json!({"userId":r.0,"email":r.1})).collect::<Vec<_>>(), "total": total}))
}

#[derive(Deserialize, Default)]
pub struct IdsQuery { #[serde(default)] pub regKeyIds: Option<String> }

pub async fn delete(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids = q.regKeyIds.unwrap_or_default().split(',').filter_map(|v| v.trim().parse::<i64>().ok()).collect::<Vec<_>>();
    if !ids.is_empty() {
        let ph = vec!["?"; ids.len()].join(",");
        let sql = format!("DELETE FROM reg_key WHERE rege_key_id IN ({ph})");
        let query = ids.iter().fold(sqlx::query(&sql), |q,id| q.bind(*id));
        let _ = query.execute(&state.pool).await;
    }
    ok_value(json!(null))
}

pub async fn clear_unused(State(state): State<Arc<AppState>>, _user: AuthUser) -> Response {
    sqlx::query("DELETE FROM reg_key WHERE count<=0 OR datetime(expire_time)<=datetime('now')").execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

fn err(code: u16, message: &str) -> Response {
    (axum::http::StatusCode::OK, Json(json!({"code":code,"message":message}))).into_response()
}
