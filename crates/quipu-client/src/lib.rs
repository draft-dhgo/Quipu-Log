//! # quipu-client
//!
//! Reference client for [`quipu-server`]: the protocol a calling service needs
//! to record audit events reliably against a **single-node** server, without
//! losing records when that node is briefly unreachable.
//!
//! `quipu-server` is single-process by design — a file lock keeps the
//! hash-chained store to one writer, which is what makes its tamper-evidence
//! simple to reason about (see the repository README's scope section). The
//! cost of that choice is that the daemon is a single point of availability:
//! while it is down or its write queue is full, every calling service's audit
//! trail would stall. Rather than bolt on multi-node replication and complicate
//! the chain, the project pushes the availability burden to the client, where
//! it is cheap and local. This crate is the reference implementation of that
//! contract:
//!
//! - **Idempotent retransmission.** Each event carries a stable
//!   `Idempotency-Key`, reused across every retry, so a retry of a POST the
//!   server already accepted is recognised and dropped instead of becoming a
//!   second audit record. See [`retry::new_idempotency_key`].
//! - **Exponential backoff with full jitter.** Transient failures retry on a
//!   bounded, randomised schedule so a fleet of clients reconnecting after an
//!   outage does not stampede the recovering daemon. See [`Backoff`].
//! - **Opt-in local disk spool.** When retries are exhausted, the event is
//!   appended (and fsynced) to a local file instead of dropped, then replayed
//!   once the server is back. This is what turns "the daemon was down" from
//!   "audit records lost" into "audit records arrived late" — and because the
//!   server keeps each event's client-set `occurred_at`, the lateness does not
//!   show in the final log. See [`Spool`].
//!
//! The crate carries **no HTTP dependency**. You implement the one-method
//! [`Transport`] trait over whatever HTTP client you already use; this crate
//! owns everything above that seam. See [`Transport`] for how to classify HTTP
//! responses into the retry loop's four outcomes.
//!
//! ## Shape of a client
//!
//! ```no_run
//! use quipu_client::{Client, Event, SendOutcome, Spool, Transport};
//! use quipu_core::{Content, EntityInput};
//!
//! // 1. Adapt your HTTP library to the Transport seam.
//! struct MyHttp { /* reqwest::blocking::Client, base url, bearer token, ... */ }
//! impl Transport for MyHttp {
//!     fn send(&self, body: &[u8], idempotency_key: &str) -> SendOutcome {
//!         // POST body to {base}/v1/logs with Authorization + Idempotency-Key
//!         // headers and a per-attempt timeout, then map the status:
//!         //   202 queued/duplicate -> Accepted / Duplicate
//!         //   408/429/5xx, connect/timeout errors -> Retry
//!         //   400/401/403/404 -> Fatal
//!         # let _ = (body, idempotency_key);
//!         SendOutcome::Accepted
//!     }
//! }
//!
//! // 2. Build a client with a disk spool for outage durability.
//! let spool = Spool::open("/var/lib/myservice/audit.spool")?;
//! let mut client = Client::new(MyHttp { /* ... */ }).with_spool(spool);
//!
//! // 3. On startup and on a timer, flush anything buffered while down.
//! client.drain_spool()?;
//!
//! // 4. Emit events; delivery never blocks on the server being up.
//! let event = Event::new(
//!     "user",
//!     EntityInput::new("u-42"),
//!     "POST",
//!     "/v1/transfer",
//!     Content::Text("wired 100".into()),
//! );
//! client.emit(&event)?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! [`quipu-server`]: https://github.com/draft-dhgo/Quipu-Log

pub mod client;
pub mod event;
pub mod retry;
pub mod spool;
pub mod transport;

pub use client::{Client, Delivery, Sleeper, ThreadSleeper};
pub use event::{Event, Target};
pub use retry::{new_idempotency_key, Backoff};
pub use spool::{DrainReport, Spool, SpoolRecord};
pub use transport::{SendOutcome, Transport};
