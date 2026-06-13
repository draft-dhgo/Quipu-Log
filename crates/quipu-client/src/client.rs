//! [`Client`]: the retransmission loop over a [`Transport`], with an optional
//! disk [`Spool`] as the last line of defence.

use crate::event::Event;
use crate::retry::{new_idempotency_key, Backoff};
use crate::spool::{DrainReport, Spool, SpoolRecord};
use crate::transport::{SendOutcome, Transport};
use std::io;

/// What `emit` resolved to after all in-process retries (and any spooling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// The server accepted the event (or recognised it as a duplicate).
    Accepted,
    /// In-process retries were exhausted; the event was appended to the spool
    /// for a later [`Client::drain_spool`]. Not a loss — the event is durable
    /// on local disk.
    Spooled,
    /// The server permanently rejected the event (`Fatal`). The reason is
    /// carried so the caller can log/quarantine it; retrying or spooling would
    /// not help.
    Rejected { reason: String },
    /// Retries were exhausted and no spool is configured, so the event could
    /// not be delivered. The caller owns it now — this is the only path on
    /// which an audit event is dropped, and it is the one a deployment that
    /// cares about completeness avoids by configuring a spool.
    Dropped { reason: String },
}

/// How to sleep between retries — injected so tests can run the real loop
/// without real time passing.
pub trait Sleeper: Send + Sync {
    fn sleep(&self, dur: std::time::Duration);
}

/// Sleeps with `std::thread::sleep`. The default for real clients.
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, dur: std::time::Duration) {
        std::thread::sleep(dur);
    }
}

/// A reference client for `quipu-server`. Owns the retransmission policy and,
/// optionally, a local spool; delegates the actual POST to a [`Transport`].
///
/// Construct with [`Client::new`], optionally attach a spool with
/// [`Client::with_spool`], then call [`Client::emit`] per event. One client is
/// cheap; share a `Transport` across several if you keep separate spools.
pub struct Client<T: Transport> {
    transport: T,
    backoff: Backoff,
    spool: Option<Spool>,
    sleeper: Box<dyn Sleeper>,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            backoff: Backoff::default(),
            spool: None,
            sleeper: Box::new(ThreadSleeper),
        }
    }

    pub fn backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Attach a disk spool: events that survive all retries are appended here
    /// instead of dropped, and replayed by [`Client::drain_spool`].
    pub fn with_spool(mut self, spool: Spool) -> Self {
        self.spool = Some(spool);
        self
    }

    /// Replace the sleeper (tests inject a no-op so the backoff loop runs
    /// instantly).
    pub fn sleeper(mut self, sleeper: Box<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Serialize, send, and — on transient failure — retry on the backoff
    /// schedule; spool the event if retries run out and a spool is attached.
    ///
    /// A fresh idempotency key is minted per call and reused across every
    /// retry of *this* event, so a retry of a POST the server already accepted
    /// is recognised and dropped rather than double-recorded.
    pub fn emit(&mut self, event: &Event) -> io::Result<Delivery> {
        let body = serde_json::to_vec(event)?;
        let key = new_idempotency_key();
        Ok(self.deliver(body, key))
    }

    /// The retry loop, shared by `emit` and (without spooling) by the first
    /// delivery of a spooled record. `key` is stable across attempts.
    fn deliver(&mut self, body: Vec<u8>, key: String) -> Delivery {
        let mut attempt = 0u32;
        loop {
            match self.transport.send(&body, &key) {
                SendOutcome::Accepted | SendOutcome::Duplicate => return Delivery::Accepted,
                SendOutcome::Fatal { reason } => return Delivery::Rejected { reason },
                SendOutcome::Retry { reason } => {
                    attempt += 1;
                    match self.backoff.delay(attempt) {
                        Some(delay) => self.sleeper.sleep(delay),
                        None => return self.exhausted(body, key, reason),
                    }
                }
            }
        }
    }

    /// Retries are spent: spool the event if we can, otherwise report it
    /// dropped.
    fn exhausted(&mut self, body: Vec<u8>, key: String, reason: String) -> Delivery {
        match &mut self.spool {
            Some(spool) => {
                let record = SpoolRecord {
                    idempotency_key: key,
                    body,
                };
                match spool.append(&record) {
                    Ok(()) => Delivery::Spooled,
                    // spool write itself failed (disk full?) — the event is
                    // genuinely lost; say so rather than silently swallowing
                    Err(e) => Delivery::Dropped {
                        reason: format!("retries exhausted ({reason}); spool write failed: {e}"),
                    },
                }
            }
            None => Delivery::Dropped { reason },
        }
    }

    /// Replay the spool through the transport. Call this on a timer, and once
    /// after start-up to flush events buffered before a restart. No-op (empty
    /// report) when no spool is attached.
    pub fn drain_spool(&mut self) -> io::Result<DrainReport> {
        match &mut self.spool {
            Some(spool) => spool.drain(&self.transport),
            None => Ok(DrainReport::default()),
        }
    }

    /// Consume the client and hand back the transport — useful for inspecting
    /// a recording transport in tests.
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Number of events currently spooled (0 when no spool is attached).
    pub fn spooled(&self) -> io::Result<usize> {
        match &self.spool {
            Some(spool) => spool.len(),
            None => Ok(0),
        }
    }
}
