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
    /// Disk-space thresholds and disk-full behaviour. Omit for the defaults
    /// (warn below 1 GiB or 10% free; keep accepting emits while full).
    #[serde(default)]
    pub health: HealthSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSection {
    pub root: PathBuf,
    pub max_segment_bytes: Option<u64>,
    pub sync_policy: Option<SyncPolicySpec>,
    pub retention_days: Option<u64>,
    /// Byte budget for the logs + relations tables. Combines with
    /// `retention_days` as OR: the oldest sealed segments are dropped as
    /// soon as either limit is exceeded.
    pub retention_max_bytes: Option<u64>,
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
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysSection {
    /// Secret key for HMAC-protected fields (raw bytes, used as-is).
    pub hmac_key_file: Option<PathBuf>,
    /// RSA public key (PEM) — enough to *write* encrypted fields.
    pub public_key_pem_file: Option<PathBuf>,
    /// RSA private key (PKCS#8 PEM). Optional by design: a write-only server
    /// should not hold it; querying clients then decrypt locally.
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

/// Disk-space thresholds (drive the `/v1/healthz` `degraded` state, the
/// low-disk warning log and the fallback notification) and the disk-full
/// emit behaviour.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSection {
    /// Warn when free space under the store root drops below this many
    /// bytes (default 1 GiB).
    pub min_free_bytes: Option<u64>,
    /// Warn when free space drops below this fraction of the filesystem
    /// (default 0.10). Either bound trips the warning.
    pub min_free_ratio: Option<f64>,
    /// When `true`, `POST /v1/logs` answers 507 immediately while the
    /// disk-full latch is set, instead of queueing events that cannot be
    /// persisted (default `false`).
    #[serde(default)]
    pub reject_emit_when_disk_full: bool,
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
        let mut ring = KeyRing::new();
        if let Some(p) = &self.keys.hmac_key_file {
            ring = ring.with_hmac_key(std::fs::read(p)?);
        }
        if let Some(p) = &self.keys.public_key_pem_file {
            ring = ring.with_public_pem(&std::fs::read_to_string(p)?)?;
        }
        if let Some(p) = &self.keys.private_key_pem_file {
            ring = ring.with_private_pem(&std::fs::read_to_string(p)?)?;
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
        let mut retention = match self.store.retention_days {
            Some(days) => RetentionPolicy::days(days),
            None => RetentionPolicy::keep_forever(),
        };
        if let Some(bytes) = self.store.retention_max_bytes {
            retention = retention.with_max_bytes(bytes);
        }
        cfg = cfg.retention(retention);
        Ok(cfg)
    }

    /// Pipeline configuration derived from the `health` section (defaults
    /// elsewhere are [`PipelineConfig::default`]'s).
    pub fn pipeline_config(&self) -> quipu_middleware::PipelineConfig {
        let mut thresholds = quipu_middleware::DiskThresholds::default();
        if let Some(n) = self.health.min_free_bytes {
            thresholds.min_free_bytes = n;
        }
        if let Some(r) = self.health.min_free_ratio {
            thresholds.min_free_ratio = r;
        }
        quipu_middleware::PipelineConfig {
            disk_thresholds: thresholds,
            reject_emit_when_disk_full: self.health.reject_emit_when_disk_full,
            ..Default::default()
        }
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
