//! The append request as it goes over the wire to `POST /v1/logs`.
//!
//! This crate deliberately does not depend on `quipu-middleware`, so the
//! request shape is defined here rather than reusing the server's internal
//! `AppendRequest`. The field set and JSON encoding match it exactly — the two
//! are kept in lockstep by [`crate::tests`] round-tripping a known body. The
//! leaf value types ([`Content`], [`EntityInput`], [`Value`]) come from
//! `quipu-core`, which both sides already share.

use quipu_core::{Content, EntityInput, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One target-entity reference inside an event. Serializes identically to the
/// server's `quipu_middleware::TargetSpec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub entity_type: String,
    pub input: EntityInput,
}

impl Target {
    pub fn new(entity_type: impl Into<String>, input: EntityInput) -> Self {
        Self {
            entity_type: entity_type.into(),
            input,
        }
    }
}

/// One audit event, ready to send. Mirrors the server's `AppendRequest`.
///
/// `occurred_at` is set when the event is *built*, not when it is finally
/// accepted — a client that buffers, retries, or spools to disk through an
/// outage can deliver an event minutes later, and the log must still record
/// when the action happened. The server keeps the client-set time precisely so
/// this holds; leave it `None` only for fire-and-forget callers that accept
/// "now on the server" semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// UTC microseconds since the unix epoch; `None` lets the server stamp it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<u64>,
    pub actor_type: String,
    pub actor: EntityInput,
    pub method: String,
    pub url: String,
    pub content: Content,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, Value>,
}

impl Event {
    /// Build an event timestamped now. The actor is the identity that
    /// performed the audited action; `method`/`url` describe the audited call.
    pub fn new(
        actor_type: impl Into<String>,
        actor: EntityInput,
        method: impl Into<String>,
        url: impl Into<String>,
        content: Content,
    ) -> Self {
        Self {
            occurred_at: Some(quipu_core::time::now_micros()),
            actor_type: actor_type.into(),
            actor,
            method: method.into(),
            url: url.into(),
            content,
            targets: Vec::new(),
            custom: BTreeMap::new(),
        }
    }

    pub fn target(mut self, target: Target) -> Self {
        self.targets.push(target);
        self
    }

    pub fn custom(mut self, name: impl Into<String>, value: Value) -> Self {
        self.custom.insert(name.into(), value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server's `AppendRequest` is `#[serde(deny_unknown_fields)]`, so any
    /// field this crate emits that the server does not know is a hard 400. This
    /// pins the emitted key set to the server's accepted set; if either side
    /// changes a field name, this test is where it surfaces.
    #[test]
    fn serialized_keys_match_server_append_request() {
        let event = Event::new(
            "user",
            EntityInput::new("u-1"),
            "POST",
            "/v1/x",
            Content::Text("body".into()),
        )
        .target(Target::new("account", EntityInput::new("acct-9")))
        .custom("amount", Value::Number(100.0));
        let json = serde_json::to_value(&event).unwrap();
        let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        // exactly the fields of quipu_server::api::AppendRequest
        assert_eq!(
            keys,
            ["actor", "actor_type", "content", "custom", "method", "occurred_at", "targets", "url"]
        );
    }

    /// Empty `targets`/`custom` and a `None` `occurred_at` are omitted, not sent
    /// as `null`/`[]` — the server defaults them, and a `null` occurred_at would
    /// fail its `Option<u64>` only if mis-encoded, so keep the body minimal.
    #[test]
    fn empty_optionals_are_omitted() {
        let mut event = Event::new(
            "svc",
            EntityInput::new("s-1"),
            "GET",
            "/v1/y",
            Content::Text("b".into()),
        );
        event.occurred_at = None;
        let json = serde_json::to_value(&event).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("occurred_at"));
        assert!(!obj.contains_key("targets"));
        assert!(!obj.contains_key("custom"));
    }
}
