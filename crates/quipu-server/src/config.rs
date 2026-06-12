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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    /// Bearer token -> role name. One token per calling service.
    pub tokens: HashMap<String, String>,
    /// Role name -> granted actions. Unknown roles are denied everything.
    pub grants: HashMap<String, Vec<ActionSpec>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionSpec {
    Emit,
    Query,
    Administer,
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
        if let Some(days) = self.store.retention_days {
            cfg = cfg.retention(RetentionPolicy::days(days));
        }
        Ok(cfg)
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
