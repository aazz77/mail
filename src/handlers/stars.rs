use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

#[derive(Deserialize)]
pub struct EmailId { #[serde(default)] pub emailId: i64 }
#[derive(Deserialize)]
pub struct ListQuery { #[serde(default)] pub emailId: i64, #[serde(default)] pub size: i64, #[serde(default)] pub full: i64 }

pub async fn add(State(state): State<Arc<AppState>>, user: AuthUser, Json(req): Json<EmailId>) -> Response {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email WHERE email_id=? AND user_id=?").bind(req.emailId).bind(user.user_id).fetch_one(&state.pool).await.unwrap_or(0);
    if exists == 0 { return err(400, "starNotExistEmail"); }
    sqlx::query("INSERT OR IGNORE INTO star(user_id,email_id) VALUES(?,?)").bind(user.user_id).bind(req.emailId).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

pub async fn cancel(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<EmailId>) -> Response {
    sqlx::query("DELETE FROM star WHERE user_id=? AND email_id=?").bind(user.user_id).bind(q.emailId).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

pub async fn list(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    let rows = sqlx::query("SELECT e.email_id,e.send_email,e.name,e.subject,e.create_time FROM star s JOIN email e ON e.email_id=s.email_id WHERE s.user_id=? AND e.is_del=0 AND s.email_id<? ORDER BY s.email_id DESC LIMIT ?")
        .bind(user.user_id).bind(q.emailId).bind(q.size.max(1)).fetch_all(&state.pool).await.unwrap_or_default();
    let list = rows.into_iter().map(|r| {
        use sqlx::Row;
        json!({"emailId":r.get::<i64,_>("email_id"),"sendEmail":r.get::<Option<String>,_>("send_email"),"name":r.get::<Option<String>,_>("name"),"subject":r.get::<Option<String>,_>("subject"),"createTime":r.get::<Option<String>,_>("create_time"),"isStar":1})
    }).collect::<Vec<_>>();
    ok_value(json!({"list": list}))
}

fn err(code: u16, message: &str) -> Response {
    (axum::http::StatusCode::OK, Json(json!({"code":code,"message":message}))).into_response()
}
