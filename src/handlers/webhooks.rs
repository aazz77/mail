use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;
use std::sync::Arc;

use crate::models::AppState;

pub async fn resend(State(state): State<Arc<AppState>>, Json(req): Json<Value>) -> Response {
    if let Some(id)=req.get("data").and_then(|v|v.get("email_id")).and_then(|v|v.as_str()) {
        sqlx::query("UPDATE email SET status=2 WHERE resend_email_id=?").bind(id).execute(&state.pool).await.unwrap();
    }
    (axum::http::StatusCode::OK, "success").into_response()
}
