use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub storage_dir: String,
    pub frontend_dir: String,
    pub jwt_secret: String,
    pub domains: Vec<String>,
    pub admin: String,
    pub cors_origins: Vec<String>,
    pub smtp: Option<SmtpConfig>,
    pub smtp_listen_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub from: String,
    pub tls: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
        let port = std::env::var("PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://data/cloud-mail.db?mode=rwc".into());
        let storage_dir = std::env::var("STORAGE_DIR").unwrap_or_else(|_| "./data/storage".into());
        let frontend_dir = std::env::var("FRONTEND_DIR").unwrap_or_else(|_| "./frontend".into());
        let jwt_secret = std::env::var("JWT_SECRET").context("JWT_SECRET is required")?;
        let domains = parse_domains(&std::env::var("DOMAINS").unwrap_or_else(|_| "[\"example.com\"]".into()))?;
        let admin = std::env::var("ADMIN").unwrap_or_else(|_| "admin@example.com".into());
        let cors_origins = parse_list(&std::env::var("CORS_ORIGINS").unwrap_or_else(|_| "http://localhost:3001".into()));
        let smtp = match std::env::var("SMTP_HOST") {
            Ok(host) => Some(SmtpConfig {
                host,
                port: std::env::var("SMTP_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(587),
                user: std::env::var("SMTP_USER").unwrap_or_default(),
                password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
                from: std::env::var("SMTP_FROM").unwrap_or_default(),
                tls: std::env::var("SMTP_TLS").ok().map(|v| v != "0" && v != "false").unwrap_or(true),
            }),
            Err(_) => None,
        };
        let smtp_listen_port = std::env::var("SMTP_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(25);

        Ok(Self {
            host,
            port,
            database_url,
            storage_dir,
            frontend_dir,
            jwt_secret,
            domains,
            admin,
            cors_origins,
            smtp,
            smtp_listen_port,
        })
    }

    pub fn domain_allowed(&self, email: &str) -> bool {
        self.domains.iter().any(|domain| {
            email.to_lowercase().ends_with(&format!("@{}", domain.to_lowercase()))
        })
    }
}

fn parse_domains(raw: &str) -> Result<Vec<String>> {
    if raw.trim_start().starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(raw) {
            return Ok(v);
        }
        let inner = raw.trim().trim_start_matches('[').trim_end_matches(']');
        return Ok(inner.split(',').map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string()).filter(|s| !s.is_empty()).collect());
    }
    Ok(raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

fn parse_list(raw: &str) -> Vec<String> {
    if raw.trim_start().starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(raw) {
            return v;
        }
        let inner = raw.trim().trim_start_matches('[').trim_end_matches(']');
        return inner.split(',').map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string()).filter(|s| !s.is_empty()).collect();
    }
    raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}
