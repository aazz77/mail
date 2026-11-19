use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sqlx::Column;
use std::sync::Arc;
use crate::models::AppState;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::handlers::{ok_value, AuthUser};

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default, alias = "emailId")] pub email_id: Option<i64>,
    #[serde(default, alias = "accountId")] pub account_id: Option<i64>,
    #[serde(default)] pub size: Option<i64>,
    #[serde(default, alias = "timeSort")] pub time_sort: Option<i64>,
    #[serde(default, alias = "allReceive")] pub all_receive: Option<i64>,
    #[serde(default)] pub full: Option<i64>,
    #[serde(default)] pub r#type: Option<i64>,
    #[serde(default, alias = "searchType")] pub search_type: Option<String>,
    #[serde(default)] pub text: Option<String>,
    #[serde(default, alias = "startDate")] pub start_date: Option<String>,
    #[serde(default, alias = "endDate")] pub end_date: Option<String>,
}

pub async fn list(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    let size = q.size.unwrap_or(10).clamp(1, 50);
    let typ = q.r#type.unwrap_or(0);
    let account_id = q.account_id.unwrap_or(0);
    let all_receive = q.all_receive.unwrap_or(0);
    let mut sql = String::from(
        "SELECT email_id,send_email,name,subject,code,text,content,cc,bcc,recipient,to_email,to_name,type,status,unread,create_time,message_id FROM email WHERE user_id=? AND type=? AND is_del=0"
    );
    let filter_account = all_receive == 0 && account_id > 0;
    if filter_account {
        sql.push_str(" AND account_id=?");
    }
    if let Some(cursor) = q.email_id.filter(|v| *v > 0) {
        if q.time_sort.unwrap_or(0) == 1 {
            sql.push_str(" AND email_id>?");
        } else {
            sql.push_str(" AND email_id<?");
        }
        sql.push_str(&format!(" ORDER BY email_id {} LIMIT ?", if q.time_sort.unwrap_or(0)==1 {"ASC"} else {"DESC"}));
        let rows = sqlx::query(&sql).bind(user.user_id).bind(typ);
        let rows = if filter_account { rows.bind(account_id) } else { rows };
        let rows = if q.email_id.unwrap_or(0)>0 { rows.bind(cursor) } else { rows };
        let rows = rows.bind(size).fetch_all(&state.pool).await.unwrap_or_default();
        return email_response(rows);
    }
    sql.push_str(&format!(" ORDER BY email_id {} LIMIT ?", if q.time_sort.unwrap_or(0)==1 {"ASC"} else {"DESC"}));
    let rows = sqlx::query(&sql).bind(user.user_id).bind(typ);
    let rows = if filter_account { rows.bind(account_id) } else { rows };
    let rows = rows.bind(size).fetch_all(&state.pool).await.unwrap_or_default();
    email_response(rows)
}

fn email_response(rows: Vec<sqlx::sqlite::SqliteRow>) -> Response {
    use sqlx::Row;
    let list = rows.into_iter().map(|row| {
        let mut map = serde_json::Map::new();
        for col in row.columns() {
            let name = col.name();
            let value = row.try_get::<Option<String>,_>(name).ok().flatten().map(Value::String)
                .or_else(|| row.try_get::<Option<i64>,_>(name).ok().flatten().map(|v| json!(v)))
                .unwrap_or(Value::Null);
            map.insert(name.into(), value);
        }
        Value::Object(map)
    }).collect::<Vec<_>>();
    ok_value(json!({"list": list, "total": list.len(), "latestEmail": json!({"emailId":0,"accountId":0,"userId":0})}))
}

pub async fn latest(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    let row: Option<(i64,i64,i64)> = sqlx::query_as(
        "SELECT email_id,account_id,user_id FROM email WHERE user_id=? AND type=? AND is_del=0 ORDER BY email_id DESC LIMIT 1"
    ).bind(user.user_id).bind(q.r#type.unwrap_or(0)).fetch_optional(&state.pool).await.unwrap();
    ok_value(row.map(|r| json!({"emailId":r.0,"accountId":r.1,"userId":r.2})).unwrap_or(json!({"emailId":0,"accountId":q.account_id.unwrap_or(0),"userId":user.user_id})))
}

#[derive(Deserialize, Default)]
pub struct IdsQuery { #[serde(default)] pub emailIds: Option<String> }

pub async fn delete(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids = ids_from(q.emailIds.unwrap_or_default());
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!("UPDATE email SET is_del=1 WHERE user_id=? AND email_id IN ({placeholders})");
    let query = sqlx::query(&sql).bind(user.user_id);
    let query = ids.iter().fold(query, |q,id| q.bind(*id));
    let _ = query.execute(&state.pool).await;
    ok_value(json!(null))
}

pub async fn read(State(state): State<Arc<AppState>>, user: AuthUser, Json(req): Json<IdsQuery>) -> Response {
    let ids = ids_from(req.emailIds.unwrap_or_default());
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!("UPDATE email SET unread=1 WHERE user_id=? AND email_id IN ({placeholders})");
    let query = sqlx::query(&sql).bind(user.user_id);
    let query = ids.iter().fold(query, |q,id| q.bind(*id));
    let _ = query.execute(&state.pool).await;
    ok_value(json!(null))
}

pub async fn att_list(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids = ids_from(q.emailIds.unwrap_or_default());
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!("SELECT att_id,user_id,email_id,account_id,key,filename,mime_type,size,type FROM attachments WHERE user_id=? AND email_id IN ({placeholders}) AND type=0");
    let query = sqlx::query(&sql).bind(user.user_id);
    let query = ids.iter().fold(query, |q,id| q.bind(*id));
    let rows = query.fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(Value::Array(rows.into_iter().map(att_json).collect()))
}

fn att_json(row: sqlx::sqlite::SqliteRow) -> Value {
    use sqlx::Row;
    json!({
        "attId": row.get::<i64,_>("att_id"), "userId": row.get::<i64,_>("user_id"),
        "emailId": row.get::<i64,_>("email_id"), "accountId": row.get::<i64,_>("account_id"),
        "key": row.get::<String,_>("key"), "filename": row.get::<Option<String>,_>("filename"),
        "mimeType": row.get::<Option<String>,_>("mime_type"), "size": row.get::<Option<i64>,_>("size"),
        "type": row.get::<i64,_>("type")
    })
}

#[derive(Deserialize)]
pub struct SendRequest {
    #[serde(default, alias = "accountId")] pub account_id: i64,
    #[serde(default)] pub name: Option<String>,
    #[serde(default)] pub send_type: Option<String>,
    #[serde(default)] pub email_id: i64,
    #[serde(default)] pub receiveEmail: Vec<String>,
    #[serde(default)] pub text: Option<String>,
    #[serde(default)] pub content: Option<String>,
    #[serde(default)] pub subject: Option<String>,
    #[serde(default)] pub attachments: Vec<AttachmentRequest>,
    #[serde(default)] pub manyType: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct AttachmentRequest {
    #[serde(default)] pub content: String,
    #[serde(default)] pub filename: String,
    #[serde(default)] pub size: Option<i64>,
    #[serde(default, alias = "contentType")] pub mime_type: Option<String>,
    #[serde(default)] pub contentId: Option<String>,
}

pub async fn send(State(state): State<Arc<AppState>>, user: AuthUser, Json(req): Json<SendRequest>) -> Response {
    if req.receiveEmail.is_empty() {
        return err(400, "emptyRecipient");
    }
    let account: Option<(i64,String)> = sqlx::query_as("SELECT account_id,email FROM account WHERE account_id=? AND user_id=? AND is_del=0")
        .bind(req.account_id).bind(user.user_id).fetch_optional(&state.pool).await.unwrap();
    let (account_id, send_email) = match account {
        Some(v) => v,
        None => return err(400, "senderAccountNotExist"),
    };
    let name = req.name.clone().filter(|v| !v.is_empty()).unwrap_or_else(|| send_email.split('@').next().unwrap_or("").into());
    let mut saved = Vec::new();
    for recipient in &req.receiveEmail {
        if !recipient.contains('@') {
            continue;
        }
        let subject = req.subject.clone().unwrap_or_default();
        let text = req.text.clone().unwrap_or_default();
        let content = req.content.clone().unwrap_or_default();
        let recipient_json = json!([{"address":recipient,"name":""}]).to_string();
        let result = sqlx::query(
            "INSERT INTO email(send_email,name,sender_email,account_id,user_id,subject,code,text,content,recipient,to_email,to_name,type,status,unread,create_time) VALUES(?,?,?,?,?,?,'',?,?,?,?,'',1,1,0,datetime('now'))"
        ).bind(&send_email).bind(&name).bind(&send_email).bind(account_id).bind(user.user_id).bind(&subject).bind(&text).bind(&content).bind(&recipient_json).bind(recipient)
            .execute(&state.pool).await;
        if let Ok(r) = result {
            let email_id = r.last_insert_rowid();
            for att in &req.attachments {
                let bytes = base64::engine::general_purpose::STANDARD.decode(att.content.trim()).unwrap_or_default();
                let key = format!("attachments/{}.{}", hash(&bytes), extension(&att.filename));
                let _ = crate::storage::put_object(&state.config.storage_dir, &key, &bytes).await;
                let _ = sqlx::query("INSERT INTO attachments(user_id,email_id,account_id,key,filename,mime_type,size,type) VALUES(?,?,?,?,?,?,?,0)")
                    .bind(user.user_id).bind(email_id).bind(account_id).bind(&key).bind(&att.filename).bind(&att.mime_type).bind(att.size.unwrap_or(bytes.len() as i64))
                    .execute(&state.pool).await;
            }
            let _ = sqlx::query("UPDATE user SET send_count=send_count+1 WHERE user_id=?").bind(user.user_id).execute(&state.pool).await;
            saved.push(json!({"emailId":email_id,"subject":subject,"recipient":recipient_json,"attList":[]}));
        }
    }

    // Attempt outbound SMTP delivery for each recipient (best-effort)
    if let Some(ref smtp) = state.config.smtp {
        for (recipient, saved_item) in req.receiveEmail.iter().zip(saved.iter()) {
            if !recipient.contains('@') {
                continue;
            }
            let email_id = saved_item.get("emailId").and_then(|v| v.as_i64()).unwrap_or(0);
            let subject = req.subject.clone().unwrap_or_default();
            let text = req.text.clone().unwrap_or_default();
            let html = req.content.clone().unwrap_or_default();
            let from = format!("{} <{}>", name, send_email);

            match send_via_smtp(smtp, &from, recipient, &subject, &text, &html).await {
                Ok(_) => {
                    tracing::info!("SMTP delivery succeeded for email {} to {}", email_id, recipient);
                    let _ = sqlx::query("UPDATE email SET status=2 WHERE email_id=?")
                        .bind(email_id).execute(&state.pool).await;
                }
                Err(e) => {
                    tracing::warn!("SMTP delivery failed for email {} to {}: {}", email_id, recipient, e);
                    // Keep status=1 (pending); Resend webhook may still update it
                }
            }
        }
    }

    // Internal delivery: if recipient is a local account, insert a received email
    for recipient in &req.receiveEmail {
        if !recipient.contains('@') {
            continue;
        }
        if !state.config.domain_allowed(recipient) {
            continue;
        }
        let account: Option<(i64, i64)> = sqlx::query_as(
            "SELECT account_id,user_id FROM account WHERE email=? COLLATE NOCASE AND is_del=0"
        ).bind(recipient).fetch_optional(&state.pool).await.unwrap_or(None);
        if let Some((acc_id, acc_user_id)) = account {
            let subject = req.subject.clone().unwrap_or_default();
            let text = req.text.clone().unwrap_or_default();
            let content = req.content.clone().unwrap_or_default();
            let recipient_json = json!([{"address":recipient,"name":""}]).to_string();
            let _ = sqlx::query(
                "INSERT INTO email(send_email,name,sender_email,account_id,user_id,subject,code,text,content,recipient,to_email,to_name,type,status,unread,create_time) VALUES(?,?,?,?,?,?,'',?,?,?,?,'',0,1,0,datetime('now'))"
            ).bind(&send_email).bind(&name).bind(&send_email).bind(acc_id).bind(acc_user_id).bind(&subject).bind(&text).bind(&content).bind(&recipient_json).bind(recipient)
                .execute(&state.pool).await;
        }
    }

    ok_value(Value::Array(saved))
}

async fn send_via_smtp(
    smtp: &crate::config::SmtpConfig,
    from: &str,
    to: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> Result<(), String> {
    use lettre::message::{MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let mailer = if smtp.tls {
        let builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
            .map_err(|e| e.to_string())?
            .port(smtp.port);
        if smtp.user.is_empty() {
            builder.build()
        } else {
            builder.credentials(Credentials::new(smtp.user.clone(), smtp.password.clone())).build()
        }
    } else {
        let builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
            .port(smtp.port);
        if smtp.user.is_empty() {
            builder.build()
        } else {
            builder.credentials(Credentials::new(smtp.user.clone(), smtp.password.clone())).build()
        }
    };

    let body = MultiPart::alternative()
        .singlepart(SinglePart::plain(text.to_string()))
        .singlepart(SinglePart::html(html.to_string()));

    let msg = Message::builder()
        .from(from.parse().map_err(|e: lettre::address::AddressError| e.to_string())?)
        .to(to.parse().map_err(|e: lettre::address::AddressError| e.to_string())?)
        .subject(subject.to_string())
        .multipart(body)
        .map_err(|e| e.to_string())?;

    mailer.send(msg).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn all_list(State(state): State<Arc<AppState>>, _user: AuthUser, Query(_q): Query<ListQuery>) -> Response {
    let rows = sqlx::query("SELECT email_id,send_email,name,subject,type,status,create_time,is_del FROM email ORDER BY email_id DESC LIMIT 50")
        .fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(json!({"list": rows.into_iter().map(|r| {
        use sqlx::Row;
        json!({"emailId":r.get::<i64,_>("email_id"),"sendEmail":r.get::<Option<String>,_>("send_email"),"name":r.get::<Option<String>,_>("name"),"subject":r.get::<Option<String>,_>("subject"),"type":r.get::<i64,_>("type"),"status":r.get::<i64,_>("status"),"createTime":r.get::<Option<String>,_>("create_time"),"isDel":r.get::<i64,_>("is_del")})
    }).collect::<Vec<_>>(), "total": 0}))
}

pub async fn all_delete(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids = ids_from(q.emailIds.unwrap_or_default());
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!("UPDATE email SET is_del=1 WHERE email_id IN ({placeholders})");
    let query = ids.iter().fold(sqlx::query(&sql), |q,id| q.bind(*id));
    let _ = query.execute(&state.pool).await;
    ok_value(json!(null))
}

pub async fn all_batch_delete(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids = ids_from(q.emailIds.unwrap_or_default());
    if ids.is_empty() { return ok_value(json!(null)); }
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!("UPDATE email SET is_del=1 WHERE email_id IN ({placeholders})");
    let query = ids.iter().fold(sqlx::query(&sql), |q,id| q.bind(*id));
    let _ = query.execute(&state.pool).await;
    ok_value(json!(null))
}

pub async fn all_latest(State(state): State<Arc<AppState>>, _user: AuthUser, Query(_q): Query<ListQuery>) -> Response {
    let rows: Vec<(i64,i64)> = sqlx::query_as("SELECT email_id,user_id FROM email ORDER BY email_id DESC LIMIT 20").fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(Value::Array(rows.into_iter().map(|r| json!({"emailId":r.0,"userId":r.1})).collect()))
}

pub async fn analysis(State(state): State<Arc<AppState>>, _user: AuthUser, Query(_q): Query<ListQuery>) -> Response {
    let rows: Vec<(i64,i64)> = sqlx::query_as("SELECT type,COUNT(*) FROM email GROUP BY type").fetch_all(&state.pool).await.unwrap_or_default();
    ok_value(json!({"emails": rows.into_iter().map(|r| json!({"type":r.0,"count":r.1})).collect::<Vec<_>>()}))
}

fn ids_from(raw: String) -> Vec<i64> {
    raw.split(',').filter_map(|v| v.trim().parse().ok()).collect()
}
fn hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new(); hasher.update(bytes);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}
fn extension(filename: &str) -> String {
    filename.rsplit('.').next().unwrap_or("bin").chars().take(16).collect()
}
fn err(code: u16, message: &str) -> Response {
    (axum::http::StatusCode::OK, Json(json!({"code":code,"message":message}))).into_response()
}
