//! # audit-middleware
//!
//! Async audit-logging middleware on top of [`audit_core`]:
//!
//! - [`pipeline`]: event-driven, non-blocking writer with retries, a
//!   disk-backed dead-letter queue and a programmable fallback hook
//! - [`filter`]: programmable pre/post filters that can exempt requests from
//!   auditing or enrich events after the response is known
//! - [`permissions`]: who may emit and who may query audit logs
//! - [`layer`]: a `tower` Layer that proxies HTTP services per endpoint and
//!   emits audit events automatically

pub mod event;
pub mod filter;
pub mod layer;
pub mod permissions;
pub mod pipeline;

pub use event::{AuditEvent, TargetSpec};
pub use filter::{FilterDecision, FilterSet, PostFilter, PreFilter, RequestInfo, ResponseInfo};
pub use layer::{ActorExtractor, AuditLayer, AuditService, EndpointRule, TargetExtractor};
pub use permissions::{Action, PermissionPolicy, Role};
pub use pipeline::{
    AuditHandle, AuditPipeline, DlqEntry, FallbackFn, MiddlewareError, PipelineConfig,
};
