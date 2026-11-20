use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::models::AppState;

/// Resend webhook. Maps the event `type` to an email delivery status, mirroring
/// `resend-service.js`. Unknown email ids are ignored (200) so Resend does not
/// circuit-break the webhook on duplicate/historical/test events.
pub async fn resend(State(state): State<Arc<AppState>>, Json(req): Json<Value>) -> Response {
    let event = req.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let data = req.get("data").unwrap_or(&Value::Null);
    let resend_id = data.get("email_id").and_then(|v| v.as_str()).unwrap_or("");

    // Default to SENT (1), then override by event type.
    let status: i64 = match event {
        "email.delivered" => 2,
        "email.bounced" => 3,
        "email.complained" => 4,
        "email.delivery_delayed" => 5,
        "email.failed" => 8,
        _ => 1,
    };
    let message: Option<Value> = match event {
        "email.bounced" => Some(json!(data.get("bounce").cloned().unwrap_or(Value::Null).to_string())),
        "email.failed" => Some(json!(
            data.get("failed").and_then(|f| f.get("reason")).and_then(|r| r.as_str()).unwrap_or("")
        )),
        _ => None,
    };

    if !resend_id.is_empty() {
        let result = if let Some(msg) = message {
            sqlx::query("UPDATE email SET status=?,message=? WHERE resend_email_id=?")
                .bind(status)
                .bind(msg.as_str().unwrap_or("").to_string())
                .bind(resend_id)
                .execute(&state.pool)
                .await
        } else {
            sqlx::query("UPDATE email SET status=?,message=NULL WHERE resend_email_id=?")
                .bind(status)
                .bind(resend_id)
                .execute(&state.pool)
                .await
        };
        if let Ok(r) = result {
            if r.rows_affected() == 0 {
                tracing::warn!("resend webhook: unknown email_id {}, type {}", resend_id, event);
            }
        }
    }
    (axum::http::StatusCode::OK, "success").into_response()
}
