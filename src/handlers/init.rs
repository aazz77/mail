use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::models::AppState;

pub async fn init(Path(secret): Path<String>, State(state): State<Arc<AppState>>) -> Response {
    if secret != state.config.jwt_secret {
        return (axum::http::StatusCode::UNAUTHORIZED, "JWT secret mismatch").into_response();
    }
    (axum::http::StatusCode::OK, "success").into_response()
}
