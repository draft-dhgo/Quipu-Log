use audit_core::{Content, EntityInput, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One target entity reference inside an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetSpec {
    pub entity_type: String,
    pub input: EntityInput,
}

impl TargetSpec {
    pub fn new(entity_type: impl Into<String>, input: EntityInput) -> Self {
        Self {
            entity_type: entity_type.into(),
            input,
        }
    }
}

/// The unit the host application hands to the middleware. Serializable so a
/// failed event can be parked in the dead-letter queue byte-for-byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// UTC-micros at event creation. This becomes the log's `timestamp`, so a
    /// log records when the audited action happened — not when an async
    /// writer (or a DLQ redrive, hours later) finally persisted it.
    pub occurred_at: u64,
    pub actor_type: String,
    pub actor: EntityInput,
    pub method: String,
    pub url: String,
    pub content: Content,
    pub targets: Vec<TargetSpec>,
    pub custom: BTreeMap<String, Value>,
}

impl AuditEvent {
    pub fn new(
        actor_type: impl Into<String>,
        actor: EntityInput,
        method: impl Into<String>,
        url: impl Into<String>,
        content: Content,
    ) -> Self {
        Self {
            occurred_at: audit_core::time::now_micros(),
            actor_type: actor_type.into(),
            actor,
            method: method.into(),
            url: url.into(),
            content,
            targets: Vec::new(),
            custom: BTreeMap::new(),
        }
    }

    pub fn target(mut self, spec: TargetSpec) -> Self {
        self.targets.push(spec);
        self
    }

    pub fn custom(mut self, name: impl Into<String>, value: Value) -> Self {
        self.custom.insert(name.into(), value);
        self
    }
}
