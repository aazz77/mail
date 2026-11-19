use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::handlers::{ok_value, AuthUser};
use crate::models::AppState;

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)] pub num: i64,
    #[serde(default)] pub size: i64,
    #[serde(default)] pub email: Option<String>,
    #[serde(default)] pub status: i64,
    #[serde(default)] pub timeSort: i64,
    #[serde(default)] pub isDel: i64,
}

pub async fn list(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    let size = q.size.clamp(1,50);
    let offset = (q.num.max(1)-1)*size;
    let mut sql = String::from("SELECT user_id,email,type,status,send_count,create_time,is_del FROM user WHERE 1=1");
    if q.status > -1 { sql.push_str(" AND status=? AND is_del=0"); }
    if q.isDel > 0 { sql.push_str(" AND is_del=?"); }
    if q.email.is_some() { sql.push_str(" AND email LIKE ?"); }
    sql.push_str(if q.timeSort==1 {" ORDER BY user_id ASC"} else {" ORDER BY user_id DESC"});
    sql.push_str(" LIMIT ? OFFSET ?");
    let query = sqlx::query(&sql);
    let query = if q.status > -1 { query.bind(q.status) } else { query };
    let query = if q.isDel > 0 { query.bind(q.isDel) } else { query };
    let query = if let Some(email) = q.email { query.bind(format!("{email}%")) } else { query };
    let rows = query.bind(size).bind(offset).fetch_all(&state.pool).await.unwrap_or_default();
    let list = rows.into_iter().map(|r| {
        use sqlx::Row;
        json!({"userId":r.get::<i64,_>("user_id"),"email":r.get::<String,_>("email"),"type":r.get::<i64,_>("type"),"status":r.get::<i64,_>("status"),"sendCount":r.get::<i64,_>("send_count"),"createTime":r.get::<Option<String>,_>("create_time"),"isDel":r.get::<i64,_>("is_del")})
    }).collect::<Vec<_>>();
    ok_value(json!({"list":list,"total":list.len()}))
}

#[derive(Deserialize)]
pub struct AddRequest { pub email: String, pub password: String, #[serde(default)] pub type_id: Option<i64> }

pub async fn add(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<AddRequest>) -> Response {
    if req.password.len()<6 || !state.config.domain_allowed(&req.email) { return err(400,"badRequest"); }
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user WHERE email=? COLLATE NOCASE").bind(&req.email).fetch_one(&state.pool).await.unwrap_or(0);
    if exists>0 { return err(400,"isRegAccount"); }
    let (salt,hash)=hash_password(&req.password);
    let type_id=req.type_id.unwrap_or(1);
    let r=sqlx::query("INSERT INTO user(email,type,password,salt) VALUES(?,?,?,?)").bind(&req.email).bind(type_id).bind(&hash).bind(&salt).execute(&state.pool).await.unwrap();
    let id=r.last_insert_rowid();
    sqlx::query("INSERT INTO account(email,name,user_id) VALUES(?,?,?)").bind(&req.email).bind(req.email.split('@').next().unwrap_or("")).bind(id).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}

#[derive(Deserialize)]
pub struct IdRequest { #[serde(default)] pub userId: i64, #[serde(default)] pub password: Option<String>, #[serde(default)] pub status: Option<i64>, #[serde(default)] pub typeId: Option<i64> }

pub async fn set_password(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<IdRequest>) -> Response {
    if let Some(p)=req.password { let (s,h)=hash_password(&p); sqlx::query("UPDATE user SET password=?,salt=? WHERE user_id=?").bind(h).bind(s).bind(req.userId).execute(&state.pool).await.unwrap(); }
    ok_value(json!(null))
}
pub async fn set_status(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<IdRequest>) -> Response {
    if let Some(s)=req.status { sqlx::query("UPDATE user SET status=? WHERE user_id=?").bind(s).bind(req.userId).execute(&state.pool).await.unwrap(); }
    ok_value(json!(null))
}
pub async fn set_type(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<IdRequest>) -> Response {
    if let Some(t)=req.typeId { sqlx::query("UPDATE user SET type=? WHERE user_id=?").bind(t).bind(req.userId).execute(&state.pool).await.unwrap(); }
    ok_value(json!(null))
}
pub async fn delete(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids=ids(q.ids.unwrap_or_default());
    let ph=vec!["?";ids.len()].join(",");
    let sql=format!("UPDATE user SET is_del=1 WHERE user_id IN ({ph})");
    let query=ids.iter().fold(sqlx::query(&sql),|q,id|q.bind(*id));
    let _=query.execute(&state.pool).await;
    ok_value(json!(null))
}
pub async fn reset_send_count(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<IdRequest>) -> Response {
    sqlx::query("UPDATE user SET send_count=0 WHERE user_id=?").bind(req.userId).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}
pub async fn restore(State(state): State<Arc<AppState>>, _user: AuthUser, Json(req): Json<IdRequest>) -> Response {
    sqlx::query("UPDATE user SET status=0 WHERE user_id=?").bind(req.userId).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}
pub async fn all_accounts(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<serde_json::Value>) -> Response {
    let user_id=q.get("userId").and_then(|v|v.as_i64()).unwrap_or(0);
    let rows: Vec<(i64,String,String)>=sqlx::query_as("SELECT account_id,email,name FROM account WHERE user_id=? ORDER BY account_id").bind(user_id).fetch_all(&state.pool).await.unwrap_or_default();
    let total = rows.len();
    ok_value(json!({"list":rows.into_iter().map(|r|json!({"accountId":r.0,"email":r.1,"name":r.2})).collect::<Vec<_>>(),"total":total}))
}
pub async fn delete_account(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<serde_json::Value>) -> Response {
    let id=q.get("accountId").and_then(|v|v.as_i64()).unwrap_or(0);
    sqlx::query("DELETE FROM account WHERE account_id=?").bind(id).execute(&state.pool).await.unwrap();
    ok_value(json!(null))
}
#[derive(Deserialize, Default)] pub struct IdsQuery { #[serde(default)] pub ids: Option<String> }
fn ids(raw:String)->Vec<i64>{raw.split(',').filter_map(|v|v.trim().parse().ok()).collect()}
fn hash_password(password:&str)->(String,String){
    use rand::RngCore; let mut salt=[0u8;16]; rand::thread_rng().fill_bytes(&mut salt);
    let salt=base64::engine::general_purpose::STANDARD.encode(salt);
    let mut h=Sha256::new(); h.update(salt.as_bytes()); h.update(password.as_bytes());
    (salt,base64::engine::general_purpose::STANDARD.encode(h.finalize()))
}
fn err(code:u16,message:&str)->Response{(axum::http::StatusCode::OK,Json(json!({"code":code,"message":message}))).into_response()}
