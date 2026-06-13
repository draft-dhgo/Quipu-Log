use super::segment::{
    chain_contains, skim, verify_chain, ChainHash, Segment, SegmentReader, CHAIN_LEN,
};
use crate::error::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".log";

/// A typed, append-only table: a directory of rolling segment files.
pub struct Table<T> {
    dir: PathBuf,
    active: Segment,
    active_seq: u64,
    /// Sealed segments: seq -> (path, max record timestamp, record count).
    /// Used by scans (read in seq order), retention (drop whole old segments)
    /// and checkpointing (table-wide record count).
    sealed: BTreeMap<u64, (PathBuf, u64, u64)>,
    max_segment_bytes: u64,
    _marker: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> Table<T> {
    pub fn open(dir: &Path, max_segment_bytes: u64) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut seqs: Vec<u64> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if let Some(num) = name
                .strip_prefix(SEGMENT_PREFIX)
                .and_then(|s| s.strip_suffix(SEGMENT_SUFFIX))
                .and_then(|s| s.parse::<u64>().ok())
            {
                seqs.push(num);
            }
        }
        seqs.sort_unstable();
        let active_seq = seqs.last().copied().unwrap_or(0);
        let mut sealed = BTreeMap::new();
        for &seq in seqs.iter().filter(|&&s| s != active_seq) {
            let path = segment_path(dir, seq);
            let (max_ts, records) = skim(&path)?
                .map(|s| (s.max_timestamp, s.records))
                .unwrap_or((0, 0));
            sealed.insert(seq, (path, max_ts, records));
        }
        // the seed only matters when the active file is brand new, i.e. the
        // table is empty — an existing active segment keeps its own header
        let active = Segment::open(&segment_path(dir, active_seq), [0; CHAIN_LEN])?;
        Ok(Self {
            dir: dir.to_path_buf(),
            active,
            active_seq,
            sealed,
            max_segment_bytes,
            _marker: PhantomData,
        })
    }

    /// Append a row. `timestamp` is the row's logical time (drives retention).
    pub fn append(&mut self, row: &T, timestamp: u64) -> Result<()> {
        let payload = bincode::serialize(row)?;
        if !self.active.is_empty()
            && self.active.len() + payload.len() as u64 > self.max_segment_bytes
        {
            self.roll()?;
        }
        self.active.append(&payload, timestamp)?;
        Ok(())
    }

    fn roll(&mut self) -> Result<()> {
        self.active.sync()?;
        self.sealed.insert(
            self.active_seq,
            (
                self.active.path().to_path_buf(),
                self.active.max_timestamp,
                self.active.records(),
            ),
        );
        self.active_seq += 1;
        // seed the new segment with the final chain value of the sealed one,
        // so the tamper-evidence chain spans segment boundaries
        let seed = self.active.last_chain();
        self.active = Segment::open(&segment_path(&self.dir, self.active_seq), seed)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.active.flush()
    }

    pub fn sync(&mut self) -> Result<()> {
        self.active.sync()
    }

    /// Stream every row in append order. The active segment is flushed first so
    /// the scan sees all appended data.
    pub fn scan(&mut self) -> Result<TableScan<T>> {
        Ok(TableScan::over(self.slices()?))
    }

    /// A point-in-time view of this table's data: every segment path with the
    /// byte length valid *right now*. A reader holding these can scan on
    /// another thread while this table keeps appending — bytes past the
    /// recorded bound are simply outside the snapshot.
    pub fn slices(&mut self) -> Result<Vec<SegmentSlice>> {
        self.active.flush()?;
        let mut slices: Vec<SegmentSlice> = self
            .sealed
            .values()
            .map(|(p, _, _)| SegmentSlice {
                path: p.clone(),
                bound: u64::MAX,
            })
            .collect();
        slices.push(SegmentSlice {
            path: self.active.path().to_path_buf(),
            bound: self.active.len(),
        });
        Ok(slices)
    }

    /// Verify the tamper-evidence hash chain across the whole table: every
    /// record's chain value must match its recomputation, and each segment's
    /// seed must equal the previous segment's final chain value. The oldest
    /// retained segment's seed is not checked against anything — retention
    /// legitimately drops old segments.
    pub fn verify(&mut self) -> Result<()> {
        self.active.flush()?;
        let mut prev: Option<ChainHash> = None;
        let mut paths: Vec<PathBuf> = self.sealed.values().map(|(p, _, _)| p.clone()).collect();
        paths.push(self.active.path().to_path_buf());
        for path in paths {
            let (seed, last) = verify_chain(&path)?;
            if let Some(p) = prev {
                if seed != p {
                    return Err(crate::error::Error::Corrupt {
                        segment: path.display().to_string(),
                        offset: 0,
                        reason: "chain seed does not match the previous segment — a segment \
                                 was removed, reordered or replaced"
                            .into(),
                    });
                }
            }
            prev = Some(last);
        }
        Ok(())
    }

    /// Delete sealed segments whose newest record is older than `cutoff_micros`.
    /// Returns the number of segments removed. The active segment is never
    /// dropped, so the most recent rows always survive.
    pub fn purge_older_than(&mut self, cutoff_micros: u64) -> Result<usize> {
        let doomed: Vec<u64> = self
            .sealed
            .iter()
            .filter(|(_, (_, max_ts, _))| *max_ts < cutoff_micros)
            .map(|(&seq, _)| seq)
            .collect();
        for seq in &doomed {
            if let Some((path, _, _)) = self.sealed.remove(seq) {
                std::fs::remove_file(path)?;
            }
        }
        Ok(doomed.len())
    }

    /// Sequence number of the segment currently being written.
    pub fn active_seq(&self) -> u64 {
        self.active_seq
    }

    /// Chain value of the newest record across the whole table (the seed of
    /// the active segment when it is still empty — same value either way).
    pub fn chain_head(&self) -> ChainHash {
        self.active.last_chain()
    }

    /// Records currently on disk across all segments. Decreases when
    /// retention unlinks sealed segments.
    pub fn record_count(&self) -> u64 {
        self.active.records() + self.sealed.values().map(|(_, _, n)| n).sum::<u64>()
    }

    /// Whether `target` is the stored chain value of any record (or a segment
    /// seed) in this table — see [`chain_contains`]. Drives checkpoint-head
    /// verification.
    pub fn contains_chain_value(&mut self, target: &ChainHash) -> Result<bool> {
        self.active.flush()?;
        for (path, _, _) in self.sealed.values() {
            if chain_contains(path, target)? {
                return Ok(true);
            }
        }
        chain_contains(self.active.path(), target)
    }
}

impl<T: Serialize + DeserializeOwned> Table<T> {
    /// Drop every row: delete all sealed segments and start a fresh active
    /// segment. Used by the DLQ redrive (read all, clear, re-append failures).
    pub fn clear(&mut self) -> Result<()> {
        let old_active = self.active.path().to_path_buf();
        self.active_seq += 1;
        // open the new segment first so the old writer is dropped before its
        // file is unlinked (required for OS-independence, e.g. Windows)
        self.active = Segment::open(&segment_path(&self.dir, self.active_seq), [0; CHAIN_LEN])?;
        std::fs::remove_file(old_active)?;
        for (_, (path, _, _)) in std::mem::take(&mut self.sealed) {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{seq:010}{SEGMENT_SUFFIX}"))
}

/// What [`rewrite_table`] did: the chain head before and after, and the
/// number of records carried over. The caller is expected to persist the
/// head transition somewhere auditable — a rewritten chain is otherwise
/// indistinguishable from a tampered one.
#[derive(Debug, Clone)]
pub struct RewriteStats {
    pub old_chain_head: ChainHash,
    pub new_chain_head: ChainHash,
    pub records: u64,
}

/// Rewrite every row of the table at `dir` through `f`, producing a *fresh*
/// hash chain (zero seed). Row order and per-row timestamps are preserved.
///
/// The rewrite goes to a sibling `<dir>.rewrite` directory first and is
/// fsynced before the swap, so a crash mid-rewrite leaves the original table
/// untouched; a crash between the two renames leaves a `<dir>.pre-rewrite`
/// backup to recover from by hand. Offline use only — the caller must hold
/// the store lock and have dropped every other handle to this table.
pub fn rewrite_table<T: Serialize + DeserializeOwned>(
    dir: &Path,
    max_segment_bytes: u64,
    mut f: impl FnMut(T) -> Result<T>,
) -> Result<RewriteStats> {
    let name = dir
        .file_name()
        .ok_or_else(|| crate::error::Error::Encode("table dir has no name".into()))?
        .to_string_lossy();
    let tmp = dir.with_file_name(format!("{name}.rewrite"));
    let backup = dir.with_file_name(format!("{name}.pre-rewrite"));
    for stale in [&tmp, &backup] {
        if stale.exists() {
            std::fs::remove_dir_all(stale)?;
        }
    }

    let mut old: Table<T> = Table::open(dir, max_segment_bytes)?;
    let old_chain_head = old.chain_head();
    let slices = old.slices()?;
    let mut fresh: Table<T> = Table::open(&tmp, max_segment_bytes)?;
    for slice in slices {
        let mut reader = SegmentReader::open_bounded(&slice.path, slice.bound)?;
        while let Some((ts, payload)) = reader.next_record()? {
            let row: T = bincode::deserialize(&payload)?;
            fresh.append(&f(row)?, ts)?;
        }
    }
    fresh.sync()?;
    let new_chain_head = fresh.chain_head();
    let records = fresh.record_count();

    // close both tables before touching their directories
    drop(old);
    drop(fresh);
    std::fs::rename(dir, &backup)?;
    std::fs::rename(&tmp, dir)?;
    std::fs::remove_dir_all(&backup)?;
    Ok(RewriteStats {
        old_chain_head,
        new_chain_head,
        records,
    })
}

/// One segment file plus the byte length that belongs to a snapshot.
#[derive(Debug, Clone)]
pub struct SegmentSlice {
    pub path: PathBuf,
    pub bound: u64,
}

pub struct TableScan<T> {
    slices: Vec<SegmentSlice>,
    current: Option<SegmentReader>,
    idx: usize,
    _marker: PhantomData<T>,
}

impl<T> TableScan<T> {
    /// Scan rows out of a set of snapshot slices (see [`Table::slices`]).
    pub fn over(slices: Vec<SegmentSlice>) -> Self {
        Self {
            slices,
            current: None,
            idx: 0,
            _marker: PhantomData,
        }
    }
}

impl<T: DeserializeOwned> TableScan<T> {
    pub fn next_row(&mut self) -> Result<Option<T>> {
        loop {
            if self.current.is_none() {
                if self.idx >= self.slices.len() {
                    return Ok(None);
                }
                let s = &self.slices[self.idx];
                self.current = Some(SegmentReader::open_bounded(&s.path, s.bound)?);
                self.idx += 1;
            }
            if let Some((_, payload)) = self.current.as_mut().unwrap().next_record()? {
                return Ok(Some(bincode::deserialize(&payload)?));
            }
            self.current = None;
        }
    }
}

impl<T: DeserializeOwned> Iterator for TableScan<T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_row().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Row {
        ts: u64,
        msg: String,
    }

    #[test]
    fn rolls_segments_scans_and_purges() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        for i in 0..50u64 {
            t.append(
                &Row {
                    ts: i,
                    msg: format!("row-{i}"),
                },
                i,
            )
            .unwrap();
        }
        t.sync().unwrap();
        let rows: Vec<Row> = t.scan().unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 50);
        let files = std::fs::read_dir(dir.path()).unwrap().count();
        assert!(files > 1, "expected rolled segments, got {files}");

        // reopen: scan still complete, then purge old segments
        drop(t);
        let mut t2: Table<Row> = Table::open(dir.path(), 256).unwrap();
        assert_eq!(t2.scan().unwrap().count(), 50);
        let purged = t2.purge_older_than(40).unwrap();
        assert!(purged > 0);
        let remaining: Vec<Row> = t2.scan().unwrap().map(|r| r.unwrap()).collect();
        assert!(remaining.len() < 50);
        // newest rows survive (active segment is never purged)
        assert_eq!(remaining.last().unwrap().msg, "row-49");
    }
}
