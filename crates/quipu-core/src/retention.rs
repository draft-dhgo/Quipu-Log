use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How long — and how big — audit logs (and their target relations) are kept.
///
/// Both limits are optional and combine as **OR**: enforcement removes the
/// oldest data as soon as *either* limit is exceeded.
///
/// - `max_age`: logs older than the window may be purged.
/// - `max_bytes`: byte budget for the logs + relations tables combined; while
///   they exceed it, the oldest sealed segments are dropped (oldest first,
///   regardless of age).
///
/// Enforcement drops whole sealed segments, so purging never rewrites data
/// and costs one `unlink` per segment — which also means it cannot break the
/// tamper-evidence hash chain (verification never checks the dropped prefix's
/// seed, and a fresh integrity checkpoint is written after every purge). Two
/// consequences of segment granularity:
///
/// - The active segment is never dropped, so `max_bytes` is a *target*, not a
///   hard ceiling: the store can exceed it by up to one active segment per
///   table until the next roll.
/// - Registries (and their meta/checkpoint bookkeeping) are intentionally not
///   purged and not counted against `max_bytes`: version history is what lets
///   old logs keep rendering as-recorded values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Keep logs whose timestamp is within this duration from "now".
    /// `None` = no age limit.
    pub max_age: Option<Duration>,
    /// Byte budget for the logs + relations tables combined.
    /// `None` = no size limit.
    pub max_bytes: Option<u64>,
}

impl RetentionPolicy {
    /// No limits — nothing is ever purged (the default).
    pub const fn keep_forever() -> Self {
        Self {
            max_age: None,
            max_bytes: None,
        }
    }

    /// Age limit only.
    pub const fn keep_for(d: Duration) -> Self {
        Self {
            max_age: Some(d),
            max_bytes: None,
        }
    }

    /// Age limit only, in days.
    pub fn days(days: u64) -> Self {
        Self::keep_for(Duration::from_secs(days * 86_400))
    }

    /// Add/replace the byte budget (combines with any age limit as OR).
    pub const fn with_max_bytes(mut self, n: u64) -> Self {
        self.max_bytes = Some(n);
        self
    }

    /// UTC-micros cutoff: records strictly older may be purged.
    /// `None` when there is no age limit.
    pub fn cutoff_micros(&self, now_micros: u64) -> Option<u64> {
        self.max_age
            .map(|d| now_micros.saturating_sub(d.as_micros() as u64))
    }
}
