use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

#[derive(Deserialize)]
pub struct EmailId { #[serde(default)] pub emailId: i64 }
#[derive(Deserialize)]
pub struct ListQuery { #[serde(default)] pub emailId: i64, #[serde(default)] pub size: i64, #[serde(default)] pub full: i64 }

pub async fn add(State(state): State<Arc<AppState>>, user: AuthUser, Json(req): Json<EmailId>) -> Response {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email WHERE email_id=? AND user_id=?")
        .bind(req.emailId).bind(user.user_id).fetch_one(&state.pool).await.unwrap_or(0);
    if exists == 0 { return err(400, "starNotExistEmail"); }
    let _ = sqlx::query("INSERT OR IGNORE INTO star(user_id,email_id) VALUES(?,?)")
        .bind(user.user_id).bind(req.emailId).execute(&state.pool).await;
    ok_value(json!(null))
}

pub async fn cancel(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<EmailId>) -> Response {
    let _ = sqlx::query("DELETE FROM star WHERE user_id=? AND email_id=?")
        .bind(user.user_id).bind(q.emailId).execute(&state.pool).await;
    ok_value(json!(null))
}

pub async fn list(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    use sqlx::{Row, Column};
    let size = if q.size > 0 { q.size.min(50) } else { 10 };
    let full = q.full == 1;

    // When emailId is 0 there is no cursor — do NOT add `email_id < 0`.
    let mut sql = String::from(
        "SELECT e.*, s.star_id FROM star AS s \
         LEFT JOIN email AS e ON e.email_id=s.email_id \
         WHERE s.user_id=? AND e.is_del=0",
    );
    if q.emailId > 0 {
        sql.push_str(" AND s.email_id<?");
    }
    sql.push_str(" ORDER BY s.email_id DESC LIMIT ?");

    let mut query = sqlx::query(&sql).bind(user.user_id);
    if q.emailId > 0 {
        query = query.bind(q.emailId);
    }
    let rows = query.bind(size).fetch_all(&state.pool).await.unwrap_or_default();

    let mut list: Vec<Value> = Vec::new();
    for row in &rows {
        let mut map = serde_json::Map::new();
        for col in row.columns() {
            let name = col.name();
            if name == "star_id" { continue; }
            let value = row.try_get::<Option<String>, _>(name).ok().flatten().map(Value::String)
                .or_else(|| row.try_get::<Option<i64>, _>(name).ok().flatten().map(|v| json!(v)))
                .unwrap_or(Value::Null);
            map.insert(name.to_string(), value);
        }
        map.insert("isStar".into(), json!(1));
        let email_id: i64 = row.get("email_id");
        if full {
            let atts = sqlx::query(
                "SELECT att_id,user_id,email_id,account_id,key,filename,mime_type,size,type \
                 FROM attachments WHERE email_id=? AND type=0 ORDER BY att_id",
            )
            .bind(email_id).fetch_all(&state.pool).await.unwrap_or_default();
            map.insert("attList".into(), Value::Array(atts.into_iter().map(|r| {
                json!({
                    "attId": r.get::<i64,_>("att_id"), "userId": r.get::<i64,_>("user_id"),
                    "emailId": r.get::<i64,_>("email_id"), "accountId": r.get::<i64,_>("account_id"),
                    "key": r.get::<String,_>("key"), "filename": r.get::<Option<String>,_>("filename"),
                    "mimeType": r.get::<Option<String>,_>("mime_type"), "size": r.get::<Option<i64>,_>("size"),
                    "type": r.get::<i64,_>("type")
                })
            }).collect()));
        } else {
            let raw = map.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let preview: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
            map.insert("listText".into(), json!(preview.chars().take(300).collect::<String>()));
            map.remove("text");
            map.remove("content");
        }
        list.push(Value::Object(map));
    }
    ok_value(json!({"list": list}))
}

fn err(code: u16, message: &str) -> Response {
    (axum::http::StatusCode::OK, Json(json!({"code":code,"message":message}))).into_response()
}
