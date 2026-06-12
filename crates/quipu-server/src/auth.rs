use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use quipu_middleware::{PermissionPolicy, Role};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Config keys with this prefix hold the SHA-256 of the token (lowercase
/// hex) instead of the token itself, so the config file is not a credential.
pub const HASH_PREFIX: &str = "sha256:";

pub fn sha256_hex(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[derive(Debug, Clone)]
pub struct TokenEntry {
    pub role: String,
    /// Unix epoch seconds; `None` never expires. At or past this instant the
    /// token is treated exactly like an unknown one (401, no detail leaked).
    pub expires: Option<u64>,
}

/// Tokens keyed by the lowercase-hex SHA-256 of the bearer token. Plaintext
/// config keys are hashed on load, so raw tokens never outlive config parsing
/// in server memory.
#[derive(Debug, Clone, Default)]
pub struct TokenMap {
    by_hash: HashMap<String, TokenEntry>,
}

impl TokenMap {
    /// `hash` must be 64 lowercase hex chars. Returns `false` (and keeps the
    /// existing entry) when the hash is already present — two config keys for
    /// one token is a mistake worth surfacing, not silently last-wins.
    pub fn insert(&mut self, hash: String, entry: TokenEntry) -> bool {
        match self.by_hash.entry(hash) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(entry);
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn contains_hash(&self, hash: &str) -> bool {
        self.by_hash.contains_key(hash)
    }

    pub fn hashes(&self) -> impl Iterator<Item = &str> {
        self.by_hash.keys().map(String::as_str)
    }
}

/// Everything the HTTP layer consults per request, swapped as one unit on
/// SIGHUP so a reload can never mix old tokens with new grants.
#[derive(Debug, Clone)]
pub struct AuthState {
    pub tokens: TokenMap,
    pub policy: PermissionPolicy,
    /// Per-token cap on queries running at once; `None` = unlimited.
    pub max_concurrent_queries: Option<u32>,
}

/// Resolve `Authorization: Bearer <token>` to the configured role plus the
/// token's hash (the per-token rate-limit key). `None` covers a
/// missing/malformed header, an unknown token, and an expired one — the
/// caller answers 401 either way, without revealing which it was.
pub fn role_for(headers: &HeaderMap, tokens: &TokenMap, now_secs: u64) -> Option<(Role, String)> {
    let token = headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    let hash = sha256_hex(token);
    let entry = tokens.by_hash.get(&hash)?;
    if entry.expires.is_some_and(|exp| now_secs >= exp) {
        return None;
    }
    Some((Role::new(entry.role.clone()), hash))
}
