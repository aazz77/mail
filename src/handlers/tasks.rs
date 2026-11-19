use std::sync::Arc;
use sqlx::SqlitePool;
use crate::config::Config;

pub fn spawn(pool: SqlitePool, _config: Arc<Config>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let _ = sqlx::query("UPDATE user SET send_count=0").execute(&pool).await;
        }
    });
}
