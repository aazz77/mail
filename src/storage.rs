use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use std::path::PathBuf;
use tokio::fs;

pub async fn init(dir: &str) -> Result<()> {
    fs::create_dir_all(dir).await.with_context(|| format!("create storage directory {dir}"))?;
    Ok(())
}

fn resolve(root: &str, key: &str) -> Result<PathBuf, StatusCode> {
    let path = PathBuf::from(root).join(key);
    let canonical_root = std::path::Path::new(root)
        .canonicalize()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let canonical_path = path
        .canonicalize()
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if !canonical_path.starts_with(canonical_root) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(canonical_path)
}

pub async fn get_object(
    Path(key): Path<String>,
    State(state): State<std::sync::Arc<crate::models::AppState>>,
) -> Response {
    let path = match resolve(&state.config.storage_dir, &key) {
        Ok(path) => path,
        Err(status) => return status.into_response(),
    };
    let data = match fs::read(&path).await {
        Ok(data) => data,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    // Serve with a browser-friendly MIME type so images/backgrounds render.
    let mime = mime_guess::from_path(&path)
        .first_or_octet_stream()
        .as_ref()
        .to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "public, max-age=31536000")
        .body(Body::from(data))
        .unwrap()
}

pub async fn put_object(root: &str, key: &str, data: &[u8]) -> Result<()> {
    let path = PathBuf::from(root).join(key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(path, data).await?;
    Ok(())
}
