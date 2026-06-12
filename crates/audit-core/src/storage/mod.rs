//! Append-only segment storage.
//!
//! A *table* is a directory of numbered segment files. Every segment starts
//! with a header (`ALOG` magic, format version byte, hash-chain seed) and
//! every record is framed as
//!
//! ```text
//! [u32 LE payload length][u32 crc32(payload)][u64 timestamp][32B chain hash][payload]
//! ```
//!
//! The chain hash (`sha256(previous chain value || payload)`, seeded across
//! segment boundaries) makes the log tamper-evident. Appends go through a
//! `BufWriter` and are flushed to the OS per batch; an optional fsync policy
//! controls durability vs. throughput. Recovery scans each segment and
//! truncates a torn tail (partial last record after a crash) instead of
//! failing. Retention deletes whole segments, which keeps purging an O(1)
//! filesystem operation. Only `std::fs`/`std::io` are used, so behaviour is
//! identical on every OS Rust targets.

mod segment;
mod table;

pub use segment::{Segment, SegmentReader};
pub use table::{SegmentSlice, Table, TableScan};
