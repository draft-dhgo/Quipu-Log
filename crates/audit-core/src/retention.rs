use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How long audit logs (and their target relations) are kept.
///
/// Enforcement drops whole sealed segments whose newest record is past the
/// window, so purging never rewrites data and costs one `unlink` per segment.
/// Registries are intentionally *not* purged: version history is what lets old
/// logs keep rendering as-recorded values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionPolicy {
    KeepForever,
    /// Keep logs whose timestamp is within the duration from "now".
    KeepFor(Duration),
}

impl RetentionPolicy {
    pub fn days(days: u64) -> Self {
        RetentionPolicy::KeepFor(Duration::from_secs(days * 86_400))
    }

    /// UTC-micros cutoff: records strictly older may be purged.
    pub fn cutoff_micros(&self, now_micros: u64) -> Option<u64> {
        match self {
            RetentionPolicy::KeepForever => None,
            RetentionPolicy::KeepFor(d) => Some(now_micros.saturating_sub(d.as_micros() as u64)),
        }
    }
}
