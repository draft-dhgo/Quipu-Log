//! # quipu-middleware
//!
//! Async audit-logging middleware on top of [`quipu_core`]:
//!
//! - [`pipeline`]: event-driven, non-blocking writer with retries, a
//!   disk-backed dead-letter queue and a programmable fallback hook
//! - [`filter`]: programmable pre/post filters that can exempt requests from
//!   auditing or enrich events after the response is known
//! - [`permissions`]: who may emit and who may query audit logs
//! - [`layer`]: a `tower` Layer that proxies HTTP services per endpoint and
//!   emits audit events automatically
//! - [`metrics`] / [`health`]: lock-free pipeline counters (queue depth, DLQ
//!   size, write latency, ...) and health flags (writer liveness, disk-full
//!   latch, low-disk warning), readable from any handle clone without
//!   touching the writer thread

pub mod event;
pub mod filter;
pub mod health;
pub mod layer;
pub mod metrics;
pub mod permissions;
pub mod pipeline;

pub use event::{AuditEvent, TargetSpec};
pub use filter::{FilterDecision, FilterSet, PostFilter, PreFilter, RequestInfo, ResponseInfo};
pub use health::{disk_usage, DiskThresholds, DiskUsage, HealthSnapshot, HealthState};
pub use layer::{ActorExtractor, AuditLayer, AuditService, EndpointRule, TargetExtractor};
pub use metrics::{LatencySnapshot, MetricsSnapshot, PipelineMetrics};
pub use permissions::{Action, PermissionPolicy, Role};
pub use pipeline::{
    AuditHandle, AuditPipeline, DlqEntry, FallbackFn, MiddlewareError, PipelineConfig, VerifyReport,
};
