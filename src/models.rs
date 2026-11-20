use std::sync::Arc;
use sqlx::SqlitePool;

use crate::config::Config;

pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}
