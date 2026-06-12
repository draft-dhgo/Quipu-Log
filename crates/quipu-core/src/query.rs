use crate::id::Uid;
use crate::model::{Content, StoredValue, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a [`TargetFilter`] compares the probe value against stored values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    #[default]
    Exact,
    /// Case-insensitive exact match. Plain fields are scanned; protected
    /// fields need [`crate::schema::FieldIndex::Exact`] declared (the
    /// lowercased token digest is looked up — no false positives).
    ExactCi,
    /// Case-insensitive prefix match. Plain fields are scanned; protected
    /// fields need [`crate::schema::FieldIndex::Prefix`] covering the probe
    /// length (prefix tokens are exact — no false positives).
    Prefix,
    /// LIKE-style substring match. Works on plain fields (in-memory scan) and
    /// on RSA fields (values are decrypted with the private key and cached
    /// per immutable version, so each value is decrypted at most once per
    /// process). One-way hashed fields (Sha256/Hmac) cannot be
    /// substring-scanned — the plaintext is never stored — unless they
    /// declare [`crate::schema::FieldIndex::Ngram`], which matches candidate
    /// digests instead (case-insensitive, may include false positives). An
    /// Ngram index also narrows RSA fields to candidates before decryption.
    Contains,
}

/// Search condition against a target entity's registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFilter {
    pub entity_type: String,
    pub field: String,
    pub value: Value,
    /// `true`: match if the entity carried this value in *any* version (so a
    /// renamed entity is still found by its old name, and a search by the
    /// current name also returns logs written before the rename).
    /// `false`: only entities whose latest, non-deleted version matches.
    #[serde(default = "default_include_past")]
    pub include_past: bool,
    #[serde(default)]
    pub mode: MatchMode,
}

fn default_include_past() -> bool {
    true
}

impl TargetFilter {
    /// Exact match, including past versions (the usual audit question).
    pub fn exact(entity_type: impl Into<String>, field: impl Into<String>, value: Value) -> Self {
        Self {
            entity_type: entity_type.into(),
            field: field.into(),
            value,
            include_past: true,
            mode: MatchMode::Exact,
        }
    }

    /// Switch to substring (LIKE) matching — see [`MatchMode::Contains`].
    pub fn contains(mut self) -> Self {
        self.mode = MatchMode::Contains;
        self
    }

    /// Switch to case-insensitive exact matching — see [`MatchMode::ExactCi`].
    pub fn exact_ci(mut self) -> Self {
        self.mode = MatchMode::ExactCi;
        self
    }

    /// Switch to prefix matching — see [`MatchMode::Prefix`].
    pub fn prefix(mut self) -> Self {
        self.mode = MatchMode::Prefix;
        self
    }

    /// Only match entities whose latest, non-deleted version matches.
    pub fn latest_only(mut self) -> Self {
        self.include_past = false;
        self
    }
}

/// Declarative log query. All set conditions are AND-ed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogQuery {
    /// Inclusive UTC-micros range.
    pub from_micros: Option<u64>,
    pub to_micros: Option<u64>,
    pub method: Option<String>,
    pub url_prefix: Option<String>,
    /// Filter by actor registry attributes (same semantics as target filters,
    /// applied to the actor's registry).
    pub actor: Option<TargetFilter>,
    /// Target conditions, AND-ed: a log matches only if it touches an entity
    /// matching *every* filter ("logs that touched X *and* Y").
    pub targets: Vec<TargetFilter>,
    /// Custom-column equality conditions.
    pub custom: BTreeMap<String, Value>,
    pub limit: Option<usize>,
}

/// Snapshot of one entity exactly as it was when the log was written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub entity_registry_uid: Uid,
    pub entity_type: String,
    pub entity_id: String,
    pub version: u32,
    /// As-recorded field values: a later rename does not alter what shows here.
    pub fields: BTreeMap<String, StoredValue>,
    pub deleted: bool,
    /// The referenced registry version could not be resolved (e.g. the
    /// registry lost data the log outlived). The log itself is still valid —
    /// one unresolvable entity must not make whole query results unreadable —
    /// so it renders with this placeholder instead of failing.
    #[serde(default)]
    pub missing: bool,
}

/// A fully resolved query hit: the raw log row plus actor/target snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogView {
    pub log_id: Uid,
    pub timestamp_micros: u64,
    /// RFC 3339, always UTC+0.
    pub timestamp: String,
    pub actor: TargetSnapshot,
    pub method: String,
    pub url: String,
    pub content: Content,
    pub targets: Vec<TargetSnapshot>,
    pub custom: BTreeMap<String, Value>,
}
