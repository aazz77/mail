use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Database(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
}

impl AppError {
    pub fn code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::Database(_) | Self::Other(_) => 500,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let code = self.code();
        let body = json!({ "code": code, "message": self.to_string() });
        (StatusCode::OK, Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
