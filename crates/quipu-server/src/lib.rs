//! # quipu-server
//!
//! Standalone audit-log daemon: [`quipu_core`]'s embedded store wrapped in
//! [`quipu_middleware`]'s async pipeline and exposed over an HTTP/JSON API,
//! so multiple services (in any language) can record and search audit logs
//! centrally — the Elasticsearch-style deployment shape, complementing the
//! embedded mode rather than replacing it.
//!
//! Key boundary: the server only ever needs the HMAC key and the RSA *public*
//! key (append + hash-based search). The private key is optional; without it
//! RSA-protected values come back as ciphertext for the querying client to
//! decrypt, keeping plaintext recovery out of the server's blast radius.

pub mod api;
pub mod auth;
pub mod config;
pub mod serve;

pub use api::{
    evaluate_health, render_prometheus, router, spawn_periodic_verify, AppState, HealthReport,
    QuerySlot, VerifyGuard,
};
pub use auth::{sha256_hex, AuthState, TokenMap};
pub use config::ServerConfig;
pub use serve::{bind, serve};
