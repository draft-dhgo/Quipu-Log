use crate::id::Uid;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Plain field value as supplied by the caller (before any protection is applied).
///
/// On disk the JSON variant is carried as its string form (`ValueRepr`):
/// bincode is a non-self-describing format and cannot deserialize
/// `serde_json::Value` directly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ValueRepr", into = "ValueRepr")]
pub enum Value {
    Text(String),
    Number(f64),
    Json(serde_json::Value),
}

#[derive(Serialize, Deserialize)]
enum ValueRepr {
    Text(String),
    Number(f64),
    Json(String),
}

impl From<Value> for ValueRepr {
    fn from(v: Value) -> Self {
        match v {
            Value::Text(s) => ValueRepr::Text(s),
            Value::Number(n) => ValueRepr::Number(n),
            Value::Json(j) => ValueRepr::Json(j.to_string()),
        }
    }
}

impl TryFrom<ValueRepr> for Value {
    type Error = String;

    fn try_from(r: ValueRepr) -> Result<Self, Self::Error> {
        Ok(match r {
            ValueRepr::Text(s) => Value::Text(s),
            ValueRepr::Number(n) => Value::Number(n),
            ValueRepr::Json(s) => Value::Json(serde_json::from_str(&s).map_err(|e| e.to_string())?),
        })
    }
}

impl Value {
    pub fn kind(&self) -> ValueKind {
        match self {
            Value::Text(_) => ValueKind::Text,
            Value::Number(_) => ValueKind::Number,
            Value::Json(_) => ValueKind::Json,
        }
    }

    /// Canonical byte representation used for hashing and for index keys.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Value::Text(s) => s.as_bytes().to_vec(),
            Value::Number(n) => format!("{n}").into_bytes(),
            Value::Json(v) => v.to_string().into_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueKind {
    Text,
    Number,
    Json,
}

/// A field value as it sits on disk, after the schema's protection was applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StoredValue {
    Plain(Value),
    /// SHA-256 of the canonical bytes (hex). Still searchable: queries hash
    /// the probe value and compare digests. The original is unrecoverable by
    /// design (though low-entropy values can be brute-forced — see
    /// [`crate::schema::FieldProtection::Sha256`]).
    Sha256(String),
    /// HMAC-SHA-256 of the canonical bytes (hex), keyed with the store's HMAC
    /// key. Still searchable: queries MAC the probe value with the same key
    /// and compare digests. The original is unrecoverable by design, and
    /// without the key the digest cannot be brute-forced from disk.
    Hmac(String),
    /// Hybrid encryption: the value is AES-256-GCM encrypted under a random
    /// data key, which is RSA-OAEP(SHA-256) wrapped with the store's public
    /// key. Recoverable with the private key via
    /// [`crate::crypto::KeyRing::decrypt`]; not searchable. GCM authenticates
    /// the ciphertext, so any in-place modification fails decryption.
    Rsa {
        wrapped_key: String,
        nonce: String,
        ciphertext: String,
    },
}

/// Audit-log body column: free text or structured JSON (request/response dumps etc).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ContentRepr", into = "ContentRepr")]
pub enum Content {
    Text(String),
    Json(serde_json::Value),
}

#[derive(Serialize, Deserialize)]
enum ContentRepr {
    Text(String),
    Json(String),
}

impl From<Content> for ContentRepr {
    fn from(c: Content) -> Self {
        match c {
            Content::Text(s) => ContentRepr::Text(s),
            Content::Json(j) => ContentRepr::Json(j.to_string()),
        }
    }
}

impl TryFrom<ContentRepr> for Content {
    type Error = String;

    fn try_from(r: ContentRepr) -> Result<Self, Self::Error> {
        Ok(match r {
            ContentRepr::Text(s) => Content::Text(s),
            ContentRepr::Json(s) => {
                Content::Json(serde_json::from_str(&s).map_err(|e| e.to_string())?)
            }
        })
    }
}

/// One row of the audit log table.
///
/// `targets` live in the relation table ([`TargetRelation`]), not here, so a log
/// can point at any number of entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub log_id: Uid,
    /// UTC+0, microseconds since the unix epoch. See [`crate::time`].
    pub timestamp: u64,
    /// Version uid of the actor's registry record at record time.
    pub actor: Uid,
    pub actor_type: String,
    /// HTTP method of the audited API call.
    pub method: String,
    /// URL of the audited API call.
    pub url: String,
    pub content: Content,
    /// Values for registered custom columns, validated against
    /// [`crate::schema::CustomColumnDef`] at append time.
    pub custom: BTreeMap<String, Value>,
}

/// Relation-table row binding a log to one target entity.
/// `entity_registry_uid` points at the exact registry *version* that was current
/// when the log was written, which is what makes as-recorded rendering possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRelation {
    pub log_id: Uid,
    pub entity_registry_uid: Uid,
    pub entity_type: String,
}
