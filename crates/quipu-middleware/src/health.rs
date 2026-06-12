//! Pipeline health: writer-thread liveness, the disk-full latch and the
//! low-disk early warning. Like [`crate::metrics`], everything here is plain
//! atomics shared between the writer thread and every handle clone — health
//! can be read even when the writer is dead, which is exactly when it
//! matters.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Free/total bytes of the filesystem holding a path (see [`disk_usage`]).
#[derive(Debug, Clone, Copy)]
pub struct DiskUsage {
    /// Bytes available to this (unprivileged) process.
    pub free_bytes: u64,
    pub total_bytes: u64,
}

impl DiskUsage {
    /// Free space as a fraction of the filesystem size (0.0 on a 0-sized fs).
    pub fn free_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.free_bytes as f64 / self.total_bytes as f64
        }
    }
}

/// Measure free/total space of the filesystem holding `path` via
/// `statvfs(3)`. `free_bytes` uses `f_bavail` (what a non-root process can
/// actually allocate), not `f_bfree`.
#[cfg(unix)]
pub fn disk_usage(path: &Path) -> std::io::Result<DiskUsage> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c_path is a valid NUL-terminated string and stat is a valid,
    // zero-initialised statvfs the call may write into.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let frsize = if stat.f_frsize > 0 {
        stat.f_frsize
    } else {
        stat.f_bsize
    } as u64;
    Ok(DiskUsage {
        free_bytes: stat.f_bavail as u64 * frsize,
        total_bytes: stat.f_blocks as u64 * frsize,
    })
}

/// Non-unix fallback: disk measurement is unsupported, callers degrade to
/// "unknown" (no warning, no degraded health) rather than failing.
#[cfg(not(unix))]
pub fn disk_usage(_path: &Path) -> std::io::Result<DiskUsage> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "disk usage measurement is only implemented for unix targets",
    ))
}

/// When is free space "low"? Either bound trips the warning (OR), mirroring
/// the retention semantics. Defaults: 1 GiB or 10% free, whichever is hit
/// first.
#[derive(Debug, Clone, Copy)]
pub struct DiskThresholds {
    pub min_free_bytes: u64,
    pub min_free_ratio: f64,
}

impl Default for DiskThresholds {
    fn default() -> Self {
        Self {
            min_free_bytes: 1024 * 1024 * 1024,
            min_free_ratio: 0.10,
        }
    }
}

impl DiskThresholds {
    pub fn is_low(&self, usage: &DiskUsage) -> bool {
        usage.free_bytes < self.min_free_bytes || usage.free_ratio() < self.min_free_ratio
    }
}

/// Shared health flags. Held behind an `Arc` by the writer thread and every
/// [`crate::AuditHandle`] clone.
///
/// The setters are public so hosts/tests can drive the state directly (e.g.
/// integration tests simulating a full disk); in normal operation the writer
/// thread maintains them.
#[derive(Debug)]
pub struct HealthState {
    writer_alive: AtomicBool,
    disk_full: AtomicBool,
    low_disk: AtomicBool,
    thresholds: DiskThresholds,
}

impl HealthState {
    pub fn new(thresholds: DiskThresholds) -> Self {
        Self {
            writer_alive: AtomicBool::new(true),
            disk_full: AtomicBool::new(false),
            low_disk: AtomicBool::new(false),
            thresholds,
        }
    }

    pub fn thresholds(&self) -> DiskThresholds {
        self.thresholds
    }

    pub fn writer_alive(&self) -> bool {
        self.writer_alive.load(Ordering::Acquire)
    }

    pub fn set_writer_alive(&self, alive: bool) {
        self.writer_alive.store(alive, Ordering::Release);
    }

    /// The ENOSPC latch: set when a write fails with storage-full, cleared
    /// when a write succeeds again or housekeeping measures free space back
    /// above the warning thresholds.
    pub fn disk_full(&self) -> bool {
        self.disk_full.load(Ordering::Acquire)
    }

    /// Returns the previous value, so callers can log only on transitions.
    pub fn set_disk_full(&self, full: bool) -> bool {
        self.disk_full.swap(full, Ordering::AcqRel)
    }

    /// The early warning: free space measured below [`DiskThresholds`].
    pub fn low_disk(&self) -> bool {
        self.low_disk.load(Ordering::Acquire)
    }

    /// Returns the previous value, so callers can log only on transitions.
    pub fn set_low_disk(&self, low: bool) -> bool {
        self.low_disk.swap(low, Ordering::AcqRel)
    }

    /// Plain-value copy for health endpoints.
    pub fn snapshot(&self) -> HealthSnapshot {
        HealthSnapshot {
            writer_alive: self.writer_alive(),
            disk_full: self.disk_full(),
            low_disk: self.low_disk(),
            thresholds: self.thresholds,
        }
    }
}

/// Plain-value copy of [`HealthState`].
#[derive(Debug, Clone, Copy)]
pub struct HealthSnapshot {
    pub writer_alive: bool,
    pub disk_full: bool,
    pub low_disk: bool,
    pub thresholds: DiskThresholds,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_trip_on_either_bound() {
        let t = DiskThresholds {
            min_free_bytes: 100,
            min_free_ratio: 0.10,
        };
        // plenty of both
        assert!(!t.is_low(&DiskUsage {
            free_bytes: 500,
            total_bytes: 1000
        }));
        // absolute bound trips even at a high ratio
        assert!(t.is_low(&DiskUsage {
            free_bytes: 50,
            total_bytes: 100
        }));
        // ratio bound trips even with many absolute bytes
        assert!(t.is_low(&DiskUsage {
            free_bytes: 1000,
            total_bytes: 100_000
        }));
    }

    #[cfg(unix)]
    #[test]
    fn disk_usage_measures_something_sane() {
        let u = disk_usage(Path::new("/")).unwrap();
        assert!(u.total_bytes > 0);
        assert!(u.free_bytes <= u.total_bytes);
    }
}
