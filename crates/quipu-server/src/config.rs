use crate::auth::{sha256_hex, AuthState, TokenEntry, TokenMap, HASH_PREFIX};
use quipu_core::{KeyRing, RetentionPolicy, StoreConfig, SyncPolicy};
use quipu_middleware::{Action, PermissionPolicy, Role};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Whole daemon configuration, loaded from one JSON file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Bind address, e.g. `127.0.0.1:7700`.
    pub listen: String,
    pub store: StoreSection,
    #[serde(default)]
    pub keys: KeysSection,
    pub auth: AuthSection,
    /// Omit to serve plain HTTP (e.g. behind a TLS-terminating proxy).
    pub tls: Option<TlsSection>,
    /// Periodic integrity verification. Omit to disable (the
    /// `POST /v1/admin/verify` endpoint works either way).
    pub verify: Option<VerifySection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSection {
    pub root: PathBuf,
    pub max_segment_bytes: Option<u64>,
    pub sync_policy: Option<SyncPolicySpec>,
    pub retention_days: Option<u64>,
    /// See [`StoreConfig::plaintext_cache`] — opt-in, keeps protected
    /// plaintexts in server memory to allow Contains search on them.
    #[serde(default)]
    pub plaintext_cache: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicySpec {
    Always,
    EveryN(u32),
    OsManaged,
}

/// All key material is referenced by file path, never inlined in the config:
/// configs travel through chat/tickets/repos far more often than key files.
///
/// Two shapes: the single-file fields are the pre-rotation form and load as
/// **key version 1**; the `hmac_keys` / `rsa_keys` lists carry explicit
/// versions for rotated deployments. The highest version of each kind is
/// *active* (protects new writes); lower versions are read-side material for
/// old records. A version may appear in only one of the two shapes.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysSection {
    /// Secret key for HMAC-protected fields (raw bytes, used as-is).
    /// Loads as HMAC key version 1.
    pub hmac_key_file: Option<PathBuf>,
    /// RSA public key (PEM) — enough to *write* encrypted fields.
    /// Loads as RSA key version 1.
    pub public_key_pem_file: Option<PathBuf>,
    /// RSA private key (PKCS#8 PEM). Optional by design: a write-only server
    /// should not hold it; querying clients then decrypt locally.
    /// Loads as RSA key version 1.
    pub private_key_pem_file: Option<PathBuf>,
    /// Versioned HMAC keys, e.g. `[{"version": 1, "file": "..."}, ...]`.
    #[serde(default)]
    pub hmac_keys: Vec<VersionedKeyFile>,
    /// Versioned RSA keypairs, e.g.
    /// `[{"version": 2, "public_key_pem_file": "...",
    ///    "private_key_pem_file": "..."}]` (either half may be omitted —
    /// write-only servers list only public keys).
    #[serde(default)]
    pub rsa_keys: Vec<VersionedRsaKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedKeyFile {
    pub version: u32,
    pub file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedRsaKey {
    pub version: u32,
    pub public_key_pem_file: Option<PathBuf>,
    pub private_key_pem_file: Option<PathBuf>,
}

/// Direct TLS termination. Like [`KeysSection`], key material is referenced
/// by file path, never inlined: configs travel through chat/tickets/repos
/// far more often than key files.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// Server certificate chain (PEM, leaf first).
    pub cert_pem_file: PathBuf,
    /// Private key for the certificate (PKCS#8/PKCS#1/SEC1 PEM).
    pub key_pem_file: PathBuf,
}

/// Background tamper-evidence verification of the whole store.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifySection {
    /// Seconds between verification passes (the first pass runs at startup).
    /// A pass that finds a chain break — or cannot run — logs at `error`.
    pub interval_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    /// Bearer token -> role. One token per calling service. Keys are either
    /// `sha256:<hex>` (recommended — the config file is then not a
    /// credential) or the plaintext token; values are either a bare role
    /// name or `{"role": ..., "expires": <unix epoch seconds>}`.
    pub tokens: HashMap<String, TokenSpec>,
    /// Role name -> granted actions. Unknown roles are denied everything.
    pub grants: HashMap<String, Vec<ActionSpec>>,
    /// Per-token cap on queries running at once (queries are full scans, so
    /// one token must not be able to monopolise the CPU). `None` = unlimited.
    #[serde(default)]
    pub max_concurrent_queries: Option<u32>,
}

/// Both historical (`"token": "role"`) and extended
/// (`"token": {"role": ..., "expires": ...}`) value shapes.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TokenSpec {
    Role(String),
    Detailed(TokenDetail),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDetail {
    pub role: String,
    /// Unix epoch seconds; omit for a non-expiring token.
    pub expires: Option<u64>,
}

impl TokenSpec {
    fn role(&self) -> &str {
        match self {
            TokenSpec::Role(r) => r,
            TokenSpec::Detailed(d) => &d.role,
        }
    }

    fn expires(&self) -> Option<u64> {
        match self {
            TokenSpec::Role(_) => None,
            TokenSpec::Detailed(d) => d.expires,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionSpec {
    Emit,
    Query,
    Administer,
}

impl AuthSection {
    /// Normalise every token key to its SHA-256: `sha256:` keys are validated
    /// hex, plaintext keys are hashed here (with a warning — the config file
    /// should not double as a credential store).
    pub fn token_map(&self) -> std::io::Result<TokenMap> {
        fn invalid(msg: String) -> std::io::Error {
            std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
        }
        let mut map = TokenMap::default();
        let mut plaintext = 0usize;
        for (key, spec) in &self.tokens {
            let entry = TokenEntry {
                role: spec.role().to_string(),
                expires: spec.expires(),
            };
            let hash = match key.strip_prefix(HASH_PREFIX) {
                Some(hex) => {
                    let hex = hex.to_ascii_lowercase();
                    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(invalid(format!(
                            "auth.tokens key '{HASH_PREFIX}{hex}' is not a 64-char hex SHA-256"
                        )));
                    }
                    hex
                }
                None => {
                    plaintext += 1;
                    sha256_hex(key)
                }
            };
            if !map.insert(hash, entry) {
                // never echo the token itself into the error/logs
                return Err(invalid(
                    "auth.tokens lists the same token twice (plaintext and sha256: \
                     forms of one token collide)"
                        .into(),
                ));
            }
        }
        if plaintext > 0 {
            tracing::warn!(
                count = plaintext,
                "plaintext tokens in auth.tokens — store them hashed instead \
                 (key 'sha256:<hex>', e.g. `echo -n $TOKEN | shasum -a 256`)"
            );
        }
        Ok(map)
    }
}

impl From<ActionSpec> for Action {
    fn from(a: ActionSpec) -> Self {
        match a {
            ActionSpec::Emit => Action::Emit,
            ActionSpec::Query => Action::Query,
            ActionSpec::Administer => Action::Administer,
        }
    }
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn keyring(&self) -> quipu_core::Result<KeyRing> {
        let dup = |kind: &str, version: u32| {
            quipu_core::Error::Crypto(format!(
                "keys: {kind} version {version} is configured twice (the single-file \
                 fields are version 1 — use distinct versions in the list form)"
            ))
        };
        let mut ring = KeyRing::new();
        let mut hmac_seen = std::collections::HashSet::new();
        let mut rsa_seen = std::collections::HashSet::new();
        if let Some(p) = &self.keys.hmac_key_file {
            hmac_seen.insert(1);
            ring = ring.with_hmac_key_version(1, std::fs::read(p)?)?;
        }
        if let Some(p) = &self.keys.public_key_pem_file {
            rsa_seen.insert(1);
            ring = ring.with_public_pem_version(1, &std::fs::read_to_string(p)?)?;
        }
        if let Some(p) = &self.keys.private_key_pem_file {
            rsa_seen.insert(1);
            ring = ring.with_private_pem_version(1, &std::fs::read_to_string(p)?)?;
        }
        for k in &self.keys.hmac_keys {
            if !hmac_seen.insert(k.version) {
                return Err(dup("hmac", k.version));
            }
            ring = ring.with_hmac_key_version(k.version, std::fs::read(&k.file)?)?;
        }
        for k in &self.keys.rsa_keys {
            if !rsa_seen.insert(k.version) {
                return Err(dup("rsa", k.version));
            }
            if let Some(p) = &k.public_key_pem_file {
                ring = ring.with_public_pem_version(k.version, &std::fs::read_to_string(p)?)?;
            }
            if let Some(p) = &k.private_key_pem_file {
                ring = ring.with_private_pem_version(k.version, &std::fs::read_to_string(p)?)?;
            }
        }
        Ok(ring)
    }

    pub fn store_config(&self) -> quipu_core::Result<StoreConfig> {
        let mut cfg = StoreConfig::new(self.store.root.clone())
            .keys(self.keyring()?)
            .plaintext_cache(self.store.plaintext_cache);
        if let Some(n) = self.store.max_segment_bytes {
            cfg = cfg.max_segment_bytes(n);
        }
        if let Some(p) = self.store.sync_policy {
            cfg = cfg.sync_policy(match p {
                SyncPolicySpec::Always => SyncPolicy::Always,
                SyncPolicySpec::EveryN(n) => SyncPolicy::EveryN(n),
                SyncPolicySpec::OsManaged => SyncPolicy::OsManaged,
            });
        }
        if let Some(days) = self.store.retention_days {
            cfg = cfg.retention(RetentionPolicy::days(days));
        }
        Ok(cfg)
    }

    /// The complete hot-reloadable auth view (tokens + grants + query cap).
    pub fn auth_state(&self) -> std::io::Result<AuthState> {
        Ok(AuthState {
            tokens: self.auth.token_map()?,
            policy: self.permission_policy(),
            max_concurrent_queries: self.auth.max_concurrent_queries,
        })
    }

    /// Deny-by-default: a token whose role has no grants can do nothing.
    pub fn permission_policy(&self) -> PermissionPolicy {
        let mut policy = PermissionPolicy::deny_by_default();
        for (role, actions) in &self.auth.grants {
            let actions: Vec<Action> = actions.iter().copied().map(Action::from).collect();
            policy = policy.grant(Role::new(role.clone()), &actions);
        }
        policy
    }
}
