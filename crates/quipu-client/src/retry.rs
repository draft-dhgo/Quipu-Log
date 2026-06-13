//! The retransmission protocol: idempotency keys and the backoff schedule.
//!
//! These are the two halves of "the server was unreachable, try again safely":
//! a stable key so a retry of an event the server *did* accept does not become
//! a second audit record (the server dedups on it — see its
//! `Idempotency-Key` window), and a bounded, jittered delay schedule so a fleet
//! of clients retrying at once does not synchronise into a thundering herd.

use std::time::Duration;

/// A fresh idempotency key: a UUIDv4 in the canonical hyphenated form. Stable
/// per *event*, not per *attempt* — the same key rides every retransmission of
/// one event so the server can recognise the duplicate. Persisted alongside the
/// event in the spool ([`crate::Spool`]) so it survives a client restart too.
pub fn new_idempotency_key() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    // RFC 4122 version 4, variant 1
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = |b: u8| (b"0123456789abcdef"[(b >> 4) as usize], b"0123456789abcdef"[(b & 0xf) as usize]);
    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let (hi, lo) = h(b);
        s.push(hi as char);
        s.push(lo as char);
    }
    s
}

/// Exponential backoff with full jitter and a cap on both per-delay length and
/// attempt count.
///
/// "Full jitter" (delay uniformly random in `[0, exp_backoff]`) rather than a
/// fixed schedule is deliberate: when a central daemon comes back after an
/// outage, every client that buffered events retries at once, and a
/// deterministic schedule would just move the stampede to the next tick. The
/// random spread is what flattens it.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// Delay before the first retry (before jitter).
    pub base: Duration,
    /// Upper bound on any single delay, after exponential growth.
    pub max_delay: Duration,
    /// Growth factor per attempt (2.0 doubles).
    pub multiplier: f64,
    /// How many retries after the first attempt fails. `0` = try once, never
    /// retry (rely on the spool, if enabled, to hold the event).
    pub max_retries: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            max_retries: 6,
        }
    }
}

impl Backoff {
    /// Delay to wait before retry number `attempt` (1-based: `attempt == 1` is
    /// the wait before the first retry). Returns `None` once `attempt` exceeds
    /// `max_retries`, which is the signal to stop retrying. The returned delay
    /// is jittered, so two calls with the same `attempt` differ.
    pub fn delay(&self, attempt: u32) -> Option<Duration> {
        if attempt == 0 || attempt > self.max_retries {
            return None;
        }
        let exp = self.base.as_secs_f64() * self.multiplier.powi((attempt - 1) as i32);
        let capped = exp.min(self.max_delay.as_secs_f64());
        let jittered = rand::Rng::gen_range(&mut rand::thread_rng(), 0.0..=capped);
        Some(Duration::from_secs_f64(jittered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_key_is_uuid_v4_shaped() {
        let k = new_idempotency_key();
        assert_eq!(k.len(), 36);
        let parts: Vec<&str> = k.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // version nibble
        assert_eq!(parts[2].as_bytes()[0], b'4');
        // variant nibble is one of 8,9,a,b
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
        // and unique across calls
        assert_ne!(new_idempotency_key(), new_idempotency_key());
    }

    #[test]
    fn backoff_grows_then_stops() {
        let b = Backoff {
            base: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            max_retries: 3,
        };
        // every delay is within [0, capped] for its attempt
        for attempt in 1..=3 {
            let d = b.delay(attempt).unwrap();
            let cap = (0.1 * 2f64.powi((attempt - 1) as i32)).min(10.0);
            assert!(d.as_secs_f64() <= cap + 1e-9, "attempt {attempt}: {d:?} > {cap}");
        }
        // exhausted past max_retries
        assert!(b.delay(4).is_none());
        assert!(b.delay(0).is_none());
    }
}
