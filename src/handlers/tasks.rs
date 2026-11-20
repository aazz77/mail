use std::sync::Arc;
use std::time::Duration;
use sqlx::SqlitePool;
use chrono::Timelike;
use crate::config::Config;
use crate::handlers::oauth;

pub fn spawn(pool: SqlitePool, _config: Arc<Config>) {
    tokio::spawn(async move {
        // Run maintenance once shortly after startup, then hourly. The daily
        // portion self-gates on the UTC hour so it fires around 00:00 UTC only.
        let mut first = true;
        loop {
            if first {
                first = false;
            } else {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }

            let hour = chrono::Utc::now().hour();
            // Reset daily send counters only for roles configured with a
            // per-day send limit (mirrors resetDaySendCount). The hourly reset
            // here is harmless for other roles because their counters are
            // enforced differently; at UTC 00:00 we reset the daily roles.
            if hour == 0 {
                let _ = sqlx::query(
                    "UPDATE user SET send_count=0 WHERE type IN \
                     (SELECT role_id FROM role WHERE send_type='day')",
                )
                .execute(&pool)
                .await;
                let _ = sqlx::query("DELETE FROM verify_record").execute(&pool).await;
            }

            // Clear expired KV entries (public tokens / analysis cache).
            crate::kv::clear_expired(&pool).await;

            // Remove unbound OAuth rows created by abandoned sign-ins.
            oauth::clear_no_bind_users(&pool).await;

            // Auto-clean old emails according to the configured retention.
            auto_clean(&pool).await;
        }
    });
}

/// Delete emails older than `auto_clean_days`, excluding users listed in
/// `auto_clean_exclude`. Deletes in batches and cascades to attachments/stars.
async fn auto_clean(pool: &SqlitePool) {
    let row: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT auto_clean_days,auto_clean_exclude FROM setting WHERE id=1",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let (days, exclude) = match row {
        Some((d, e)) if d > 0 => (d, e),
        _ => return,
    };

    let cutoff = chrono::Local::now()
        .checked_sub_signed(chrono::Duration::days(days))
        .unwrap_or_else(chrono::Local::now)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let exclusions: Vec<String> = exclude
        .unwrap_or_default()
        .split(|c| c == ',' || c == '，')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let excluded_ids: Vec<i64> = if exclusions.is_empty() {
        Vec::new()
    } else {
        let placeholders = vec!["?"; exclusions.len()].join(",");
        let sql = format!(
            "SELECT user_id FROM user WHERE email COLLATE NOCASE IN ({})",
            placeholders
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        for email in &exclusions {
            q = q.bind(email.clone());
        }
        q.fetch_all(pool).await.unwrap_or_default()
    };

    let mut sql = String::from("SELECT email_id FROM email WHERE create_time < ?");
    if !excluded_ids.is_empty() {
        let placeholders = vec!["?"; excluded_ids.len()].join(",");
        sql.push_str(&format!(" AND user_id NOT IN ({})", placeholders));
    }
    sql.push_str(" LIMIT 95");

    loop {
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        q = q.bind(cutoff.clone());
        for id in &excluded_ids {
            q = q.bind(*id);
        }
        let ids = q.fetch_all(pool).await.unwrap_or_default();
        if ids.is_empty() {
            break;
        }
        delete_emails_by_ids(pool, &ids).await;
        if ids.len() < 95 {
            break;
        }
    }
}

/// Physically delete a set of emails and their dependent rows.
pub async fn delete_emails_by_ids(pool: &SqlitePool, ids: &[i64]) {
    if ids.is_empty() {
        return;
    }
    let placeholders = vec!["?"; ids.len()].join(",");
    let sql_att = format!("DELETE FROM attachments WHERE email_id IN ({})", placeholders);
    let sql_star = format!("DELETE FROM star WHERE email_id IN ({})", placeholders);
    let sql_email = format!("DELETE FROM email WHERE email_id IN ({})", placeholders);
    let mut qa = sqlx::query(&sql_att);
    let mut qs = sqlx::query(&sql_star);
    let mut qe = sqlx::query(&sql_email);
    for id in ids {
        qa = qa.bind(*id);
        qs = qs.bind(*id);
        qe = qe.bind(*id);
    }
    let _ = qa.execute(pool).await;
    let _ = qs.execute(pool).await;
    let _ = qe.execute(pool).await;
}
