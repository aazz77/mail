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

/// Build the WHERE clause + ordered binds shared by the list query, the total
/// count query, and (partly) the latest-email query.
struct ListFilters {
    where_sql: String,
    binds: Vec<FilterBind>,
}

#[derive(Clone)]
enum FilterBind {
    Text(String),
    Num(i64),
}

fn build_list_filters(q: &ListQuery, user: &AuthUser, with_cursor: bool) -> ListFilters {
    let typ = q.r#type.unwrap_or(0);
    let account_id = q.account_id.unwrap_or(0);
    let all_receive = q.all_receive.unwrap_or(0);
    let time_sort = q.time_sort.unwrap_or(0);

    let mut parts: Vec<String> = Vec::new();
    let mut binds: Vec<FilterBind> = Vec::new();

    parts.push("e.user_id=?".into());
    binds.push(FilterBind::Num(user.user_id));
    parts.push("e.type=?".into());
    binds.push(FilterBind::Num(typ));
    parts.push("e.is_del=0".into());
    parts.push("a.is_del=0".into());
    if all_receive == 0 {
        parts.push("e.account_id=?".into());
        binds.push(FilterBind::Num(account_id));
    }
    if with_cursor {
        if let Some(cursor) = q.email_id.filter(|v| *v > 0) {
            parts.push(if time_sort == 1 {
                "e.email_id>?"
            } else {
                "e.email_id<?"
            }
            .into());
            binds.push(FilterBind::Num(cursor));
        }
    }

    // Text search by searchType — mirrors emailListFilters.
    if let Some(text) = q.text.as_ref().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let pattern = format!("%{}%", text);
        match q.search_type.as_deref().unwrap_or("") {
            "subject" => {
                parts.push("e.subject COLLATE NOCASE LIKE ?".into());
                binds.push(FilterBind::Text(pattern));
            }
            "content" => {
                parts.push("(e.text COLLATE NOCASE LIKE ? OR e.content COLLATE NOCASE LIKE ?)".into());
                binds.push(FilterBind::Text(pattern.clone()));
                binds.push(FilterBind::Text(pattern));
            }
            "sender" => {
                parts.push("e.name COLLATE NOCASE LIKE ?".into());
                binds.push(FilterBind::Text(pattern));
            }
            "senderAddress" => {
                parts.push("e.send_email COLLATE NOCASE LIKE ?".into());
                binds.push(FilterBind::Text(pattern));
            }
            "recipientAddress" => {
                parts.push("e.to_email COLLATE NOCASE LIKE ?".into());
                binds.push(FilterBind::Text(pattern));
            }
            _ => {}
        }
    }

    // Date range filter (scoped to this user).
    let has_start = q.start_date.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
    let has_end = q.end_date.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
    if has_start || has_end {
        let mut sub = vec!["user_id=?".to_string()];
        let mut sub_binds: Vec<FilterBind> = vec![FilterBind::Num(user.user_id)];
        if let Some(s) = q.start_date.as_ref().filter(|s| !s.is_empty()) {
            sub.push("create_time>=?".into());
            sub_binds.push(FilterBind::Text(s.clone()));
        }
        if let Some(e) = q.end_date.as_ref().filter(|s| !s.is_empty()) {
            sub.push("create_time<=?".into());
            sub_binds.push(FilterBind::Text(e.clone()));
        }
        parts.push(format!(
            "e.email_id IN (SELECT email_id FROM email WHERE {})",
            sub.join(" AND ")
        ));
        binds.extend(sub_binds);
    }

    ListFilters {
        where_sql: parts.join(" AND "),
        binds,
    }
}

pub async fn list(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    use sqlx::Row;
    let size = q.size.unwrap_or(10).clamp(1, 50);
    let time_sort = q.time_sort.unwrap_or(0);
    let full = q.full.unwrap_or(1) == 1;
    let order = if time_sort == 1 { "ASC" } else { "DESC" };

    let filters = build_list_filters(&q, &user, true);

    // Main list query: join account (for is_del) and left-join star.
    let columns = if full {
        "e.*, s.star_id"
    } else {
        "e.email_id,e.send_email,e.name,e.subject,e.code,e.recipient,e.cc,e.to_email,e.type,e.status,e.message,e.unread,e.create_time,e.is_del,e.text,e.content,s.star_id"
    };
    let list_sql = format!(
        "SELECT {columns} FROM email AS e \
         INNER JOIN account AS a ON a.account_id=e.account_id \
         LEFT JOIN star AS s ON s.email_id=e.email_id AND s.user_id=? \
         WHERE {where_sql} ORDER BY e.email_id {order} LIMIT ?",
        where_sql = filters.where_sql,
    );
    let mut list_query = sqlx::query(&list_sql).bind(user.user_id);
    for b in &filters.binds {
        list_query = match b {
            FilterBind::Text(v) => list_query.bind(v.clone()),
            FilterBind::Num(n) => list_query.bind(*n),
        };
    }
    let rows = list_query.bind(size).fetch_all(&state.pool).await.unwrap_or_default();

    // Total count (no cursor).
    let count_filters = build_list_filters(&q, &user, false);
    let count_sql = format!(
        "SELECT COUNT(*) FROM email AS e \
         INNER JOIN account AS a ON a.account_id=e.account_id \
         WHERE {}",
        count_filters.where_sql
    );
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &count_filters.binds {
        count_query = match b {
            FilterBind::Text(v) => count_query.bind(v.clone()),
            FilterBind::Num(n) => count_query.bind(*n),
        };
    }
    let total = count_query.fetch_one(&state.pool).await.unwrap_or(0);

    // Latest email in this view (no cursor) for the client's sync anchor.
    let typ = q.r#type.unwrap_or(0);
    let account_id = q.account_id.unwrap_or(0);
    let all_receive = q.all_receive.unwrap_or(0);
    let mut latest_sql = String::from(
        "SELECT email_id,account_id,user_id FROM email WHERE user_id=? AND type=? AND is_del=0",
    );
    if all_receive == 0 {
        latest_sql.push_str(" AND account_id=?");
    }
    latest_sql.push_str(" ORDER BY email_id DESC LIMIT 1");
    let mut latest_q = sqlx::query_as::<_, (i64, i64, i64)>(&latest_sql)
        .bind(user.user_id)
        .bind(typ);
    if all_receive == 0 {
        latest_q = latest_q.bind(account_id);
    }
    let latest_row = latest_q.fetch_optional(&state.pool).await.ok().flatten();
    let latest_email = latest_row
        .map(|r| json!({"emailId": r.0, "accountId": r.1, "userId": r.2}))
        .unwrap_or(json!({"emailId": 0, "accountId": account_id, "userId": user.user_id}));

    // Convert rows to JSON, adding isStar and (for full) attList.
    let mut list: Vec<Value> = Vec::new();
    for row in &rows {
        let mut map = serde_json::Map::new();
        for col in row.columns() {
            let name = col.name();
            if name == "star_id" {
                continue;
            }
            let value = row.try_get::<Option<String>, _>(name).ok().flatten().map(Value::String)
                .or_else(|| row.try_get::<Option<i64>, _>(name).ok().flatten().map(|v| json!(v)))
                .unwrap_or(Value::Null);
            map.insert(name.to_string(), value);
        }
        let star_id: Option<i64> = row.try_get("star_id").ok().flatten();
        map.insert("isStar".into(), json!(if star_id.is_some() { 1 } else { 0 }));
        if full {
            let email_id: i64 = row.get("email_id");
            let atts = sqlx::query(
                "SELECT att_id,user_id,email_id,account_id,key,filename,mime_type,size,type \
                 FROM attachments WHERE email_id=? AND type=0 ORDER BY att_id",
            )
            .bind(email_id)
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
            map.insert("attList".into(), Value::Array(atts.into_iter().map(att_json).collect()));
        }
        list.push(Value::Object(map));
    }

    ok_value(json!({"list": list, "total": total, "latestEmail": latest_email}))
}

pub async fn latest(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<ListQuery>) -> Response {
    // Original: return received emails newer than `emailId`, for this account
    // (unless allReceive), with attachments and a compact listText.
    let email_id = q.email_id.unwrap_or(0);
    let account_id = q.account_id.unwrap_or(0);
    let all_receive = q.all_receive.unwrap_or(0);

    let mut sql = String::from(
        "SELECT e.* FROM email AS e \
         INNER JOIN account AS a ON a.account_id=e.account_id \
         WHERE e.email_id>? AND e.user_id=? AND e.is_del=0 AND a.is_del=0 AND e.type=0",
    );
    if all_receive == 0 {
        sql.push_str(" AND e.account_id=?");
    }
    sql.push_str(" ORDER BY e.email_id DESC LIMIT 50");

    let mut query = sqlx::query(&sql).bind(email_id).bind(user.user_id);
    if all_receive == 0 {
        query = query.bind(account_id);
    }
    let rows = query.fetch_all(&state.pool).await.unwrap_or_default();

    use sqlx::Row;
    let mut list: Vec<Value> = Vec::new();
    for row in &rows {
        let mut map = serde_json::Map::new();
        for col in row.columns() {
            let name = col.name();
            let value = row.try_get::<Option<String>, _>(name).ok().flatten().map(Value::String)
                .or_else(|| row.try_get::<Option<i64>, _>(name).ok().flatten().map(|v| json!(v)))
                .unwrap_or(Value::Null);
            map.insert(name.to_string(), value);
        }
        let id: i64 = row.get("email_id");
        let atts = sqlx::query(
            "SELECT att_id,user_id,email_id,account_id,key,filename,mime_type,size,type \
             FROM attachments WHERE email_id=? AND type=0 ORDER BY att_id",
        )
        .bind(id)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        map.insert("attList".into(), Value::Array(atts.into_iter().map(att_json).collect()));
        map.insert("isStar".into(), json!(0));
        // compact preview text (300 chars max), whitespace collapsed
        let raw = map.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let preview: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
        map.insert("listText".into(), json!(preview.chars().take(300).collect::<String>()));
        list.push(Value::Object(map));
    }
    ok_value(Value::Array(list))
}

#[derive(Deserialize, Default)]
pub struct IdsQuery { #[serde(default)] pub emailIds: Option<String> }

pub async fn delete(State(state): State<Arc<AppState>>, user: AuthUser, Query(q): Query<IdsQuery>) -> Response {
    let ids = ids_from(q.emailIds.unwrap_or_default());
    if ids.is_empty() { return ok_value(json!(null)); }
    let setting = crate::handlers::auth::current_setting(&state).await;
    let sync_delete = setting["sync_delete"].as_i64().unwrap_or(0) == 0; // 0 = OPEN
    if sync_delete {
        // Only physically delete emails owned by this user.
        let owned: Vec<i64> = {
            let ph = vec!["?"; ids.len()].join(",");
            let sql = format!("SELECT email_id FROM email WHERE user_id=? AND email_id IN ({ph})");
            let mut query = sqlx::query_scalar::<_, i64>(&sql).bind(user.user_id);
            for id in &ids { query = query.bind(*id); }
            query.fetch_all(&state.pool).await.unwrap_or_default()
        };
        crate::handlers::tasks::delete_emails_by_ids(&state.pool, &owned).await;
        return ok_value(json!(null));
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql = format!("UPDATE email SET is_del=1 WHERE user_id=? AND email_id IN ({placeholders})");
    let mut query = sqlx::query(&sql).bind(user.user_id);
    for id in &ids { query = query.bind(*id); }
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
    // Original /allEmail/delete is a physical delete by the admin.
    let ids = ids_from(q.emailIds.unwrap_or_default());
    crate::handlers::tasks::delete_emails_by_ids(&state.pool, &ids).await;
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

pub async fn analysis(State(state): State<Arc<AppState>>, _user: AuthUser, Query(q): Query<serde_json::Value>) -> Response {
    use sqlx::Row;
    let time_zone = q.get("timeZone").and_then(|v| v.as_str()).unwrap_or("UTC");

    // Offset in hours between local timezone and UTC.
    let diff_hours: i64 = parse_tz_offset_hours(time_zone);
    let tz_mod = if diff_hours >= 0 { format!("+{} hours", diff_hours) } else { format!("{} hours", diff_hours) };
    let tz_back = if -diff_hours >= 0 { format!("+{} hours", -diff_hours) } else { format!("{} hours", -diff_hours) };

    // Summary counters.
    let number_count: Value = sqlx::query(
        "SELECT \
           COALESCE(e.receiveTotal,0) AS receiveTotal, COALESCE(e.sendTotal,0) AS sendTotal, \
           COALESCE(e.delReceiveTotal,0) AS delReceiveTotal, COALESCE(e.delSendTotal,0) AS delSendTotal, \
           COALESCE(e.normalReceiveTotal,0) AS normalReceiveTotal, COALESCE(e.normalSendTotal,0) AS normalSendTotal, \
           COALESCE(u.userTotal,0) AS userTotal, COALESCE(u.normalUserTotal,0) AS normalUserTotal, COALESCE(u.delUserTotal,0) AS delUserTotal, \
           COALESCE(a.accountTotal,0) AS accountTotal, COALESCE(a.normalAccountTotal,0) AS normalAccountTotal, COALESCE(a.delAccountTotal,0) AS delAccountTotal \
         FROM \
           (SELECT \
              SUM(CASE WHEN type=0 THEN 1 ELSE 0 END) AS receiveTotal, \
              SUM(CASE WHEN type=1 THEN 1 ELSE 0 END) AS sendTotal, \
              SUM(CASE WHEN type=0 AND is_del=1 THEN 1 ELSE 0 END) AS delReceiveTotal, \
              SUM(CASE WHEN type=1 AND is_del=1 THEN 1 ELSE 0 END) AS delSendTotal, \
              SUM(CASE WHEN type=0 AND is_del=0 THEN 1 ELSE 0 END) AS normalReceiveTotal, \
              SUM(CASE WHEN type=1 AND is_del=0 THEN 1 ELSE 0 END) AS normalSendTotal \
            FROM email) e \
         CROSS JOIN \
           (SELECT COUNT(*) AS userTotal, SUM(CASE WHEN is_del=1 THEN 1 ELSE 0 END) AS delUserTotal, \
              SUM(CASE WHEN is_del=0 THEN 1 ELSE 0 END) AS normalUserTotal FROM user) u \
         CROSS JOIN \
           (SELECT COUNT(*) AS accountTotal, SUM(CASE WHEN is_del=1 THEN 1 ELSE 0 END) AS delAccountTotal, \
              SUM(CASE WHEN is_del=0 THEN 1 ELSE 0 END) AS normalAccountTotal FROM account) a",
    )
    .fetch_one(&state.pool)
    .await
    .ok()
    .map(|row| {
        let mut m = serde_json::Map::new();
        for c in row.columns() {
            let n = c.name();
            let v: i64 = row.try_get(n).unwrap_or(0);
            m.insert(n.to_string(), json!(v));
        }
        Value::Object(m)
    })
    .unwrap_or(json!({}));

    // Top senders (name ratio).
    let name_ratio: Value = {
        let rows = sqlx::query(
            "SELECT name, COUNT(*) AS total FROM email \
             WHERE type=0 AND name IS NOT NULL AND name<>'noreply' AND name<>'' \
             GROUP BY name ORDER BY total DESC LIMIT 6",
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        Value::Array(rows.into_iter().map(|r| {
            json!({
                "name": r.get::<Option<String>, _>("name"),
                "total": r.get::<i64, _>("total")
            })
        }).collect())
    };

    // Per-day counts for the past 15 days (excluding today), padded with zeros.
    let user_day = day_counts(&state, "user", &tz_mod, &tz_back).await;
    let receive_day = day_counts(&state, "email AND type=0", &tz_mod, &tz_back).await;
    let send_day = day_counts(&state, "email AND type=1", &tz_mod, &tz_back).await;

    // daySendTotal from KV cache (send_day_count:YYYY-MM-DD).
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let day_send_total: i64 = crate::kv::get(&state.pool, &format!("send_day_count:{}", today))
        .await
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    ok_value(json!({
        "numberCount": number_count,
        "userDayCount": user_day,
        "receiveRatio": { "nameRatio": name_ratio },
        "emailDayCount": { "receiveDayCount": receive_day, "sendDayCount": send_day },
        "daySendTotal": day_send_total
    }))
}

/// Count rows per day over the last 15 completed days (excluding today), in
/// the supplied timezone offset, and pad missing days with zero. `source` is
/// either "user", "email AND type=0" or "email AND type=1".
async fn day_counts(state: &Arc<AppState>, source: &str, tz_mod: &str, tz_back: &str) -> Value {
    use sqlx::Row;
    let table = source.split_whitespace().next().unwrap_or("email");
    let extra = source.strip_prefix(table).unwrap_or("").trim();
    // `extra` may already begin with "AND ..." (e.g. "email AND type=0").
    let where_extra = if extra.is_empty() {
        String::new()
    } else if extra.to_uppercase().starts_with("AND") {
        format!(" {}", extra)
    } else {
        format!(" AND {}", extra)
    };
    let sql = format!(
        "SELECT DATE(create_time, ?) AS date, COUNT(*) AS total FROM {table} \
         WHERE 1=1{where_extra} \
           AND create_time >= datetime('now', ?, 'start of day', '-15 days', ?) \
           AND create_time < datetime('now', ?, 'start of day', ?) \
         GROUP BY DATE(create_time, ?) ORDER BY date ASC"
    );
    let rows = sqlx::query(&sql)
        .bind(tz_mod)
        .bind(tz_mod).bind(tz_back)
        .bind(tz_mod).bind(tz_back)
        .bind(tz_mod)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
    let counts: std::collections::HashMap<String, i64> = rows.iter().map(|r| {
        (r.get::<Option<String>, _>("date").unwrap_or_default(), r.get::<i64, _>("total"))
    }).collect();

    // Build the last 15 completed days (yesterday going back 15 days).
    let today = chrono::Local::now().date_naive();
    let mut out: Vec<Value> = Vec::new();
    for i in (1..=15).rev() {
        let day = today - chrono::Duration::days(i);
        let key = day.format("%Y-%m-%d").to_string();
        let total = counts.get(&key).copied().unwrap_or(0);
        out.push(json!({"date": key, "total": total}));
    }
    Value::Array(out)
}

/// Parse a timezone offset from forms like "UTC+08:00", "Asia/Shanghai" (best effort).
fn parse_tz_offset_hours(tz: &str) -> i64 {
    // Explicit offset like UTC+8 / GMT-5 / +08:00
    for prefix in ["UTC", "GMT"] {
        if let Some(rest) = tz.strip_prefix(prefix) {
            if let Some(sign) = rest.chars().next() {
                if sign == '+' || sign == '-' {
                    let num: &str = &rest[1..];
                    if let Ok(mut h) = num.parse::<i64>() {
                        if sign == '-' { h = -h; }
                        return h;
                    }
                    if let Some(h) = num.split(':').next().and_then(|v| v.parse::<i64>().ok()) {
                        return if sign == '-' { -h } else { h };
                    }
                }
            }
            // bare "UTC" / "UTC+8:00" without sign
        }
    }
    // Well-known zones.
    match tz {
        "Asia/Shanghai" | "Asia/Hong_Kong" | "Asia/Singapore" | "Asia/Taipei" => 8,
        "Asia/Tokyo" | "Asia/Seoul" => 9,
        "America/Los_Angeles" => -8,
        "America/New_York" => -5,
        "Europe/London" => 0,
        _ => 0,
    }
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
