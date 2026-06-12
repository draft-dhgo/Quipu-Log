//! Lightweight pipeline metrics: plain atomics, no metrics framework.
//!
//! The pipeline increments counters on its hot path (one atomic op each);
//! hosts read a consistent-enough [`MetricsSnapshot`] whenever they like —
//! e.g. `quipu-server` renders one as a Prometheus text exposition on
//! `GET /metrics`. Snapshots never round-trip the writer thread, so they
//! keep working even when the writer is wedged or dead.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

/// Upper bounds (seconds) of the write-latency histogram buckets. A final
/// implicit `+Inf` bucket catches everything slower.
pub const LATENCY_BUCKETS_SECS: [f64; 9] = [0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0];

/// Shared, lock-free pipeline counters. One instance lives behind an `Arc`
/// in every [`crate::AuditHandle`] clone and in the writer thread.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    /// Emit commands enqueued but not yet picked up by the writer.
    queue_depth: AtomicI64,
    /// Events currently parked in the dead-letter queue.
    dlq_entries: AtomicU64,
    /// Events durably appended to the store.
    writes_ok: AtomicU64,
    /// Individual failed write attempts that were retried.
    write_retries: AtomicU64,
    /// Events that exhausted retries (or hit disk-full) and went to the DLQ.
    writes_parked: AtomicU64,
    /// Events lost outright: the store *and* the DLQ both failed. The
    /// fallback hook is the only remaining record of these.
    events_lost: AtomicU64,
    /// Emits rejected at the caller because the bounded queue was full.
    emit_rejected_queue_full: AtomicU64,
    /// Emits rejected at the caller because the disk-full latch was set
    /// (only with [`crate::PipelineConfig::reject_emit_when_disk_full`]).
    emit_rejected_disk_full: AtomicU64,
    /// Cumulative bucket counts for successful-write latency.
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_SECS.len()],
    latency_count: AtomicU64,
    latency_sum_micros: AtomicU64,
}

impl PipelineMetrics {
    pub(crate) fn queue_inc(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn queue_dec(&self) {
        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn set_dlq_entries(&self, n: u64) {
        self.dlq_entries.store(n, Ordering::Relaxed);
    }

    pub(crate) fn dlq_inc(&self) {
        self.dlq_entries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn write_ok(&self, latency: Duration) {
        self.writes_ok.fetch_add(1, Ordering::Relaxed);
        let secs = latency.as_secs_f64();
        for (i, bound) in LATENCY_BUCKETS_SECS.iter().enumerate() {
            if secs <= *bound {
                self.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_micros
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
    }

    pub(crate) fn retry(&self) {
        self.write_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn parked(&self) {
        self.writes_parked.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn lost(&self) {
        self.events_lost.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rejected_queue_full(&self) {
        self.emit_rejected_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rejected_disk_full(&self) {
        self.emit_rejected_disk_full.fetch_add(1, Ordering::Relaxed);
    }

    /// A point-in-time copy of every counter. Individual counters are read
    /// independently (relaxed), which is fine for monitoring.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queue_depth: self.queue_depth.load(Ordering::Relaxed).max(0) as u64,
            dlq_entries: self.dlq_entries.load(Ordering::Relaxed),
            writes_ok: self.writes_ok.load(Ordering::Relaxed),
            write_retries: self.write_retries.load(Ordering::Relaxed),
            writes_parked: self.writes_parked.load(Ordering::Relaxed),
            events_lost: self.events_lost.load(Ordering::Relaxed),
            emit_rejected_queue_full: self.emit_rejected_queue_full.load(Ordering::Relaxed),
            emit_rejected_disk_full: self.emit_rejected_disk_full.load(Ordering::Relaxed),
            write_latency: LatencySnapshot {
                buckets: std::array::from_fn(|i| {
                    (
                        LATENCY_BUCKETS_SECS[i],
                        self.latency_buckets[i].load(Ordering::Relaxed),
                    )
                }),
                count: self.latency_count.load(Ordering::Relaxed),
                sum_seconds: self.latency_sum_micros.load(Ordering::Relaxed) as f64 / 1e6,
            },
        }
    }
}

/// Plain-value copy of [`PipelineMetrics`] (see [`PipelineMetrics::snapshot`]).
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub queue_depth: u64,
    pub dlq_entries: u64,
    pub writes_ok: u64,
    pub write_retries: u64,
    pub writes_parked: u64,
    pub events_lost: u64,
    pub emit_rejected_queue_full: u64,
    pub emit_rejected_disk_full: u64,
    pub write_latency: LatencySnapshot,
}

/// Prometheus-style cumulative histogram of successful-write latency.
#[derive(Debug, Clone)]
pub struct LatencySnapshot {
    /// `(upper_bound_seconds, cumulative_count)` per bucket; the implicit
    /// `+Inf` bucket equals [`count`](Self::count).
    pub buckets: [(f64, u64); LATENCY_BUCKETS_SECS.len()],
    pub count: u64,
    pub sum_seconds: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_are_cumulative() {
        let m = PipelineMetrics::default();
        m.write_ok(Duration::from_micros(800)); // <= 1ms and everything above
        m.write_ok(Duration::from_millis(30)); // <= 50ms and above
        let s = m.snapshot();
        assert_eq!(s.write_latency.count, 2);
        let get = |bound: f64| {
            s.write_latency
                .buckets
                .iter()
                .find(|(b, _)| *b == bound)
                .unwrap()
                .1
        };
        assert_eq!(get(0.0005), 0);
        assert_eq!(get(0.001), 1);
        assert_eq!(get(0.025), 1);
        assert_eq!(get(0.05), 2);
        assert_eq!(get(1.0), 2);
        assert!(s.write_latency.sum_seconds > 0.03);
    }

    #[test]
    fn queue_depth_never_renders_negative() {
        let m = PipelineMetrics::default();
        m.queue_dec(); // pathological ordering
        assert_eq!(m.snapshot().queue_depth, 0);
    }
}
