-- Generic key/value store used by public API tokens and analysis cache,
-- replacing the KV binding used by the original Cloudflare Workers version.
CREATE TABLE IF NOT EXISTS kv_store (
    kv_key TEXT PRIMARY KEY,
    kv_value TEXT,
    expire_at INTEGER
);
