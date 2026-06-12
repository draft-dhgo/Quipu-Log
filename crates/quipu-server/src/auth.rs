use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use quipu_middleware::Role;
use std::collections::HashMap;

/// Resolve `Authorization: Bearer <token>` to the configured role.
/// `None` covers both a missing/malformed header and an unknown token — the
/// caller answers 401 either way, without revealing which it was.
pub fn role_for(headers: &HeaderMap, tokens: &HashMap<String, String>) -> Option<Role> {
    let token = headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    tokens.get(token).map(|role| Role::new(role.clone()))
}
