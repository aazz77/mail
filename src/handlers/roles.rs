use axum::extract::{Query, State};
use axum::response::Response;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

pub async fn add(State(state): State<Arc<AppState>>, user: AuthUser, Json(req): Json<Value>) -> Response {
    let name=req.get("name").and_then(|v|v.as_str()).unwrap_or("").to_string();
    let perms=req.get("permIds").and_then(|v|v.as_array()).cloned().unwrap_or_default();
    let ban=req.get("banEmail").and_then(|v|v.as_array()).cloned().unwrap_or_default();
    let domains=req.get("availDomain").and_then(|v|v.as_array()).cloned().unwrap_or_default();
    let r=sqlx::query("INSERT INTO role(name,ban_email,avail_domain,user_id,send_count,send_type,account_count) VALUES(?,?,?,?,?,?,?)")
        .bind(&name).bind(join(&ban)).bind(join(&domains)).bind(user.user_id)
        .bind(req.get("sendCount").and_then(|v|v.as_i64()).unwrap_or(0))
        .bind(req.get("sendType").and_then(|v|v.as_str()).unwrap_or("count"))
        .bind(req.get("accountCount").and_then(|v|v.as_i64()).unwrap_or(0))
        .execute(&state.pool).await.unwrap();
    let role_id=r.last_insert_rowid();
    for perm in perms { if let Some(id)=perm.as_i64(){ sqlx::query("INSERT INTO role_perm(role_id,perm_id) VALUES(?,?)").bind(role_id).bind(id).execute(&state.pool).await.unwrap(); } }
    ok_value(json!(null))
}
pub async fn set(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<Value>) -> Response {
    let id=req.get("roleId").and_then(|v|v.as_i64()).unwrap_or(0);
    let name=req.get("name").and_then(|v|v.as_str()).unwrap_or("");
    let ban=req.get("banEmail").and_then(|v|v.as_array()).cloned().unwrap_or_default();
    let domains=req.get("availDomain").and_then(|v|v.as_array()).cloned().unwrap_or_default();
    sqlx::query("UPDATE role SET name=?,ban_email=?,avail_domain=? WHERE role_id=?").bind(name).bind(join(&ban)).bind(join(&domains)).bind(id).execute(&state.pool).await.unwrap();
    sqlx::query("DELETE FROM role_perm WHERE role_id=?").bind(id).execute(&state.pool).await.unwrap();
    if let Some(perms)=req.get("permIds").and_then(|v|v.as_array()) { for p in perms { if let Some(pid)=p.as_i64(){sqlx::query("INSERT INTO role_perm(role_id,perm_id) VALUES(?,?)").bind(id).bind(pid).execute(&state.pool).await.unwrap();} } }
    ok_value(json!(null))
}
pub async fn set_default(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<Value>) -> Response {
    let id=req.get("roleId").and_then(|v|v.as_i64()).unwrap_or(0);
    sqlx::query("UPDATE role SET is_default=0").execute(&state.pool).await.unwrap();
    sqlx::query("UPDATE role SET is_default=1 WHERE role_id=?").bind(id).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}
pub async fn list(State(state): State<Arc<AppState>>, _user: AuthUser) -> Response {
    let rows: Vec<(i64,String,String,String,i64,String)>=sqlx::query_as("SELECT role_id,name,ban_email,avail_domain,is_default,send_type FROM role ORDER BY sort,role_id").fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(Value::Array(rows.into_iter().map(|r|json!({"roleId":r.0,"name":r.1,"banEmail":r.2.split(',').filter(|v|!v.is_empty()).collect::<Vec<_>>(),"availDomain":r.3.split(',').filter(|v|!v.is_empty()).collect::<Vec<_>>(),"isDefault":r.4,"sendType":r.5})).collect()))
}
pub async fn tree(State(state): State<Arc<AppState>>, _user: AuthUser) -> Response {
    let rows: Vec<(i64,String,Option<String>,i64,f64)>=sqlx::query_as("SELECT perm_id,name,perm_key,pid,sort FROM perm ORDER BY sort,perm_id").fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(Value::Array(rows.into_iter().map(|r|json!({"permId":r.0,"name":r.1,"permKey":r.2,"pid":r.3,"sort":r.4})).collect()))
}
pub async fn select_use(State(state): State<Arc<AppState>>, _user: AuthUser) -> Response {
    let rows: Vec<(i64,String,i64)>=sqlx::query_as("SELECT role_id,name,is_default FROM role ORDER BY sort,role_id").fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(Value::Array(rows.into_iter().map(|r|json!({"roleId":r.0,"name":r.1,"isDefault":r.2})).collect()))
}
pub async fn delete(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<serde_json::Value>) -> Response {
    let id=q.get("roleId").and_then(|v|v.as_i64()).unwrap_or(0);
    sqlx::query("UPDATE user SET type=1 WHERE type=?").bind(id).execute(&state.pool).await.unwrap();
    sqlx::query("DELETE FROM role_perm WHERE role_id=?").bind(id).execute(&state.pool).await.unwrap();
    sqlx::query("DELETE FROM role WHERE role_id=? AND is_default=0").bind(id).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}
fn join(values:&[Value])->String{values.iter().filter_map(|v|v.as_str()).collect::<Vec<_>>().join(",")}
