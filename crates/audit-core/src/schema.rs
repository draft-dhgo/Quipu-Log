use crate::model::ValueKind;
use serde::{Deserialize, Serialize};

/// How a registry field is transformed before hitting disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldProtection {
    None,
    /// One-way SHA-256. Equality search keeps working (probe is hashed too);
    /// the plaintext is never stored. No key to manage — but the digest is
    /// deterministic and unsalted, so low-entropy values (SSNs, phone
    /// numbers, ...) can be brute-forced by anyone with disk access; prefer
    /// [`FieldProtection::Hmac`] for those.
    Sha256,
    /// One-way HMAC-SHA-256 keyed with [`crate::KeyRing::with_hmac_key`].
    /// Equality search keeps working (probes are MACed with the same key);
    /// without the key the stored digests cannot be brute-forced.
    Hmac,
    /// Hybrid AES-256-GCM + RSA-OAEP(SHA-256) with the store's public key.
    /// Decryptable with the private key, but not searchable.
    Rsa,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub kind: ValueKind,
    pub protection: FieldProtection,
    /// Indexed fields support [`crate::query::TargetFilter`] lookups
    /// (current and historical values). RSA-protected fields cannot be indexed.
    pub indexed: bool,
    pub required: bool,
}

impl FieldDef {
    pub fn text(name: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: ValueKind::Text,
            protection: FieldProtection::None,
            indexed: false,
            required: false,
        }
    }

    pub fn indexed(mut self) -> Self {
        self.indexed = true;
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn kind(mut self, kind: ValueKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn protection(mut self, p: FieldProtection) -> Self {
        self.protection = p;
        self
    }
}

/// Field layout for one entity (or actor) type. Creating the schema is what
/// "creates the registry table" for that type — it must exist before entities
/// of the type can be registered or referenced by a log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeSchema {
    pub type_name: String,
    pub fields: Vec<FieldDef>,
}

impl TypeSchema {
    pub fn new(type_name: &str, fields: Vec<FieldDef>) -> Self {
        Self {
            type_name: type_name.to_string(),
            fields,
        }
    }

    pub fn field(&self, name: &str) -> Option<&FieldDef> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// Example target type: a `name` you can search by (current or past) plus a
/// free-form description. Field sets are fully customizable per type — this is
/// only the out-of-the-box default.
pub fn default_target_type() -> TypeSchema {
    TypeSchema::new(
        "default_target",
        vec![
            FieldDef::text("name").indexed().required(),
            FieldDef::text("description"),
        ],
    )
}

/// Example actor type: searchable `name` and `role`.
pub fn default_actor_type() -> TypeSchema {
    TypeSchema::new(
        "default_actor",
        vec![
            FieldDef::text("name").indexed().required(),
            FieldDef::text("role").indexed(),
        ],
    )
}

/// Declaration of an extra audit-log column. Custom columns are themselves
/// registry-managed: definitions are persisted in the meta table and values are
/// validated against `kind` on every append.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomColumnDef {
    pub name: String,
    pub kind: ValueKind,
    pub required: bool,
    /// `required` is only enforced for logs whose event time is at or after
    /// this UTC-micros instant. Filled in automatically by
    /// [`crate::AuditStore::define_custom_column`] — making a column required
    /// must not retroactively invalidate events that were created (e.g.
    /// parked in a DLQ) before the requirement existed, or their redrive
    /// would fail forever.
    pub required_since: Option<u64>,
}

impl CustomColumnDef {
    pub fn new(name: &str, kind: ValueKind) -> Self {
        Self {
            name: name.to_string(),
            kind,
            required: false,
            required_since: None,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
}
