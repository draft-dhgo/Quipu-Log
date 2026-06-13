//! # quipu-core
//!
//! Embedded, OS-independent audit-log storage engine.
//!
//! - Append-only segment files with CRC framing (pure `std::fs`, no OS-specific APIs)
//! - Typed, versioned entity/actor registries (search by current *or* past attribute
//!   values; logs always render the values as they were at record time)
//! - Per-field protection: SHA-256 hashing (searchable) or RSA-OAEP encryption
//! - Custom audit-log columns (text / number / json) managed through a registry
//! - Retention windows enforced by whole-segment drops
//!
//! The async event pipeline, filters, DLQ and HTTP proxy live in `quipu-middleware`;
//! this crate is the synchronous storage and query core underneath it.

pub mod checkpoint;
pub mod crypto;
pub mod error;
pub mod id;
pub mod model;
pub mod query;
pub mod registry;
pub mod retention;
pub mod schema;
pub mod storage;
pub mod store;
pub mod time;
mod tokens;

pub use checkpoint::Checkpoint;
pub use crypto::{KeyRing, KeyVersion, KEYLESS};
pub use error::{Error, Result};
pub use id::Uid;
pub use model::{AuditLog, Content, StoredValue, TargetRelation, Value, ValueKind};
pub use query::{LogQuery, LogView, MatchMode, TargetFilter, TargetSnapshot};
pub use registry::{EntityInput, FieldTokens};
pub use retention::RetentionPolicy;
pub use schema::{
    default_actor_type, default_target_type, CustomColumnDef, FieldDef, FieldIndex,
    FieldProtection, TypeSchema,
};
pub use store::{
    AnchorHook, AuditStore, ReadSnapshot, RekeyEvent, RekeyedTable, StoreConfig, SyncPolicy,
};
