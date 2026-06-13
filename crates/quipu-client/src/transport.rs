//! The seam between this crate's protocol and your HTTP library.
//!
//! `quipu-client` owns the *protocol* — idempotency keys, the backoff
//! schedule, the disk spool — and deliberately carries no HTTP dependency, so
//! it does not force `reqwest` vs `ureq` vs a hand-rolled socket on the host
//! application. You implement [`Transport`] over whatever client you already
//! have; the one job is to turn one POST into a [`SendOutcome`].
//!
//! The classification in [`SendOutcome`] is the whole contract: the retry loop
//! only knows "accepted / already-had-it / try-again / give-up", and it is the
//! transport's job to map HTTP status codes onto those four. A miscategorised
//! status is the one bug that matters here — see each variant's doc for which
//! codes belong where.

/// What one POST attempt resolved to, from the retry loop's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Server accepted the event (HTTP 202 `{"status":"queued"}`). Done.
    Accepted,
    /// Server recognised the idempotency key and did **not** create a second
    /// record (HTTP 202 `{"status":"duplicate"}`). Treated as success: a
    /// retry of an event the server already had is exactly what the key is
    /// for. Map the `duplicate` status body here.
    Duplicate,
    /// Transient failure — retry after backoff. Map here: connection refused
    /// or reset, timeouts, DNS failure, HTTP 408/429/502/503/504, and the
    /// audit-specific 503 the server returns when its write queue is full.
    Retry { reason: String },
    /// Permanent failure — do not retry; the spool would just replay a request
    /// the server keeps rejecting. Map here: 400 (malformed/over-cap event),
    /// 401/403 (bad or unauthorised token), 404. The event is handed back so
    /// the caller can log or quarantine it.
    Fatal { reason: String },
}

/// A single attempt to POST one serialized event with its idempotency key.
///
/// Implementations must:
/// - send `body` (already-serialized JSON for the server's `POST /v1/logs`) as
///   the request body with `Content-Type: application/json`,
/// - set the `Idempotency-Key` request header to `idempotency_key`,
/// - apply their own per-attempt timeout (the retry loop does not interrupt a
///   hung call — a transport that blocks forever blocks the loop forever), and
/// - classify the result into a [`SendOutcome`], never panicking.
///
/// `send` is intentionally synchronous and `&self`: the reference client and
/// its spool are blocking by design (the failure mode that matters,
/// "the daemon is down", is not made better by async), and `&self` lets one
/// `Transport` back many [`Client`](crate::Client)s or be shared across
/// threads. An async host can wrap the call in `spawn_blocking`.
pub trait Transport {
    fn send(&self, body: &[u8], idempotency_key: &str) -> SendOutcome;
}
