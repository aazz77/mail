//! Lightweight key/value store backed by SQLite, replacing the Cloudflare KV
//! binding used by the original Workers version. Values are plain strings;
//! an optional unix-timestamp `expire_at` enables TTL semantics.

use sqlx::SqlitePool;

/// Return the stored value for `key` when it exists and has not expired.
pub async fn get(pool: &SqlitePool, key: &str) -> Option<String> {
    let row: (String, Option<i64>) = sqlx::query_as(
        "SELECT kv_value, expire_at FROM kv_store WHERE kv_key=?",
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;

    let (value, expire_at) = row;
    if let Some(exp) = expire_at {
        let now = chrono::Utc::now().timestamp();
        if exp > 0 && exp <= now {
            return None;
        }
    }
    Some(value)
}

/// Store `value` under `key`. `ttl_secs == 0` means no expiry.
pub async fn put(pool: &SqlitePool, key: &str, value: &str, ttl_secs: i64) {
    let expire_at = if ttl_secs > 0 {
        chrono::Utc::now().timestamp() + ttl_secs
    } else {
        0
    };
    let _ = sqlx::query(
        "INSERT INTO kv_store(kv_key,kv_value,expire_at) VALUES(?,?,?) \
         ON CONFLICT(kv_key) DO UPDATE SET kv_value=excluded.kv_value, expire_at=excluded.expire_at",
    )
    .bind(key)
    .bind(value)
    .bind(expire_at)
    .execute(pool)
    .await;
}

pub async fn delete(pool: &SqlitePool, key: &str) {
    let _ = sqlx::query("DELETE FROM kv_store WHERE kv_key=?")
        .bind(key)
        .execute(pool)
        .await;
}

/// Remove every expired entry. Called by the daily maintenance task.
pub async fn clear_expired(pool: &SqlitePool) {
    let now = chrono::Utc::now().timestamp();
    let _ = sqlx::query("DELETE FROM kv_store WHERE expire_at > 0 AND expire_at <= ?")
        .bind(now)
        .execute(pool)
        .await;
}
