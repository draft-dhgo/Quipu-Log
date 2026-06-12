use super::segment::{
    chain_contains, skim, verify_chain, ChainHash, Segment, SegmentReader, CHAIN_LEN,
};
use crate::error::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

const SEGMENT_PREFIX: &str = "seg-";
const SEGMENT_SUFFIX: &str = ".log";
const META_SUFFIX: &str = ".meta";

/// Sidecar metadata persisted next to each *sealed* segment
/// (`seg-NNNNNNNNNN.meta`): the segment's time-range bounds and record count.
/// Written once at seal time, so reopening a table never has to re-skim
/// sealed segments, and time-range scans can skip out-of-range segments
/// without opening them. The sidecar is a *pruning/recovery hint only* — it
/// is rebuilt from a skim when missing or unreadable, and the
/// tamper-evidence chain never depends on it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SegmentMeta {
    /// `u64::MAX` when the segment holds no records.
    min_timestamp: u64,
    max_timestamp: u64,
    records: u64,
}

/// In-memory bookkeeping for one sealed segment.
#[derive(Debug, Clone)]
struct SealedSeg {
    path: PathBuf,
    meta: SegmentMeta,
}

/// A typed, append-only table: a directory of rolling segment files.
pub struct Table<T> {
    dir: PathBuf,
    active: Segment,
    active_seq: u64,
    /// Sealed segments by sequence number. Used by scans (read in seq order),
    /// retention (drop whole old segments) and checkpointing (record count).
    sealed: BTreeMap<u64, SealedSeg>,
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
            let meta = match read_meta(&meta_path(dir, seq)) {
                Some(m) => m,
                None => {
                    // sidecar missing/unreadable (e.g. crash between seal and
                    // meta write): rebuild it from a one-time skim
                    let m = skim(&path)?
                        .map(|s| SegmentMeta {
                            min_timestamp: s.min_timestamp,
                            max_timestamp: s.max_timestamp,
                            records: s.records,
                        })
                        .unwrap_or(SegmentMeta {
                            min_timestamp: u64::MAX,
                            max_timestamp: 0,
                            records: 0,
                        });
                    write_meta(&meta_path(dir, seq), &m);
                    m
                }
            };
            sealed.insert(seq, SealedSeg { path, meta });
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
        let meta = SegmentMeta {
            min_timestamp: self.active.min_timestamp,
            max_timestamp: self.active.max_timestamp,
            records: self.active.records(),
        };
        // best-effort sidecar: a lost write is repaired by a skim on reopen
        write_meta(&meta_path(&self.dir, self.active_seq), &meta);
        self.sealed.insert(
            self.active_seq,
            SealedSeg {
                path: self.active.path().to_path_buf(),
                meta,
            },
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
    /// byte length valid *right now*, plus the segment's time-range bounds
    /// and sequence number (which make time-range pruning and positional
    /// cursors possible). A reader holding these can scan on another thread
    /// while this table keeps appending — bytes past the recorded bound are
    /// simply outside the snapshot.
    pub fn slices(&mut self) -> Result<Vec<SegmentSlice>> {
        self.active.flush()?;
        let mut slices: Vec<SegmentSlice> = self
            .sealed
            .iter()
            .map(|(&seq, s)| SegmentSlice {
                path: s.path.clone(),
                bound: u64::MAX,
                seq,
                min_ts: s.meta.min_timestamp,
                max_ts: s.meta.max_timestamp,
            })
            .collect();
        slices.push(SegmentSlice {
            path: self.active.path().to_path_buf(),
            bound: self.active.len(),
            seq: self.active_seq,
            min_ts: self.active.min_timestamp,
            max_ts: self.active.max_timestamp,
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
        let mut paths: Vec<PathBuf> = self.sealed.values().map(|s| s.path.clone()).collect();
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
            .filter(|(_, s)| s.meta.max_timestamp < cutoff_micros)
            .map(|(&seq, _)| seq)
            .collect();
        for seq in &doomed {
            if let Some(s) = self.sealed.remove(seq) {
                std::fs::remove_file(s.path)?;
                let _ = std::fs::remove_file(meta_path(&self.dir, *seq));
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
        self.active.records() + self.sealed.values().map(|s| s.meta.records).sum::<u64>()
    }

    /// Whether `target` is the stored chain value of any record (or a segment
    /// seed) in this table — see [`chain_contains`]. Drives checkpoint-head
    /// verification.
    pub fn contains_chain_value(&mut self, target: &ChainHash) -> Result<bool> {
        self.active.flush()?;
        for s in self.sealed.values() {
            if chain_contains(&s.path, target)? {
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
        let old_seqs: Vec<u64> = self.sealed.keys().copied().collect();
        self.active_seq += 1;
        // open the new segment first so the old writer is dropped before its
        // file is unlinked (required for OS-independence, e.g. Windows)
        self.active = Segment::open(&segment_path(&self.dir, self.active_seq), [0; CHAIN_LEN])?;
        std::fs::remove_file(old_active)?;
        for (_, s) in std::mem::take(&mut self.sealed) {
            std::fs::remove_file(s.path)?;
        }
        for seq in old_seqs {
            let _ = std::fs::remove_file(meta_path(&self.dir, seq));
        }
        Ok(())
    }
}

fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{seq:010}{SEGMENT_SUFFIX}"))
}

fn meta_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{seq:010}{META_SUFFIX}"))
}

fn read_meta(path: &Path) -> Option<SegmentMeta> {
    let bytes = std::fs::read(path).ok()?;
    bincode::deserialize(&bytes).ok()
}

/// Best-effort: the sidecar is a hint, not a source of truth, so a failed
/// write only means a skim on the next open.
fn write_meta(path: &Path, meta: &SegmentMeta) {
    if let Ok(bytes) = bincode::serialize(meta) {
        let _ = std::fs::write(path, bytes);
    }
}

/// One segment file plus the byte length that belongs to a snapshot, its
/// sequence number, and its time-range bounds (`min_ts == u64::MAX` when the
/// segment holds no records).
#[derive(Debug, Clone)]
pub struct SegmentSlice {
    pub path: PathBuf,
    pub bound: u64,
    pub seq: u64,
    pub min_ts: u64,
    pub max_ts: u64,
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

/// Physical position of a record inside a table snapshot: (segment sequence
/// number, record index within that segment). Append-only storage makes a
/// position permanent — a record never moves, so positions are stable across
/// snapshots and survive concurrent appends. Retention can only *remove*
/// whole old segments, which scans handle by skipping absent sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub seq: u64,
    pub idx: u64,
}

/// Time/position-bounded scan over snapshot slices, in ascending or
/// descending position order. This is the scalable query primitive:
///
/// - segments entirely outside `[from, to]` are never opened (their bounds
///   come from the slice metadata),
/// - segments entirely before/after a positional cursor are never opened,
/// - rows outside the time range are skipped *before* deserialization (the
///   timestamp lives in the frame header).
///
/// Descending order buffers one segment at a time (segments are read
/// front-to-back, then drained in reverse) — memory is bounded by
/// `max_segment_bytes`, never by table size.
pub struct PositionedScan<T> {
    /// Remaining slices in scan order (reversed up front for descending).
    slices: Vec<SegmentSlice>,
    slice_idx: usize,
    desc: bool,
    from: u64,
    to: u64,
    /// Exclusive start position in scan direction: ascending yields only
    /// positions > after, descending only positions < after.
    after: Option<Position>,
    /// Forward reader state (ascending).
    current: Option<(u64, u64, SegmentReader)>, // (seq, next idx, reader)
    /// Buffered rows of the current segment (descending), drained from the back.
    buffered: Vec<(Position, u64, Vec<u8>)>,
    /// Segments actually opened — observability for pruning tests/benches.
    segments_opened: u64,
    _marker: PhantomData<T>,
}

impl<T> PositionedScan<T> {
    pub fn new(
        mut slices: Vec<SegmentSlice>,
        desc: bool,
        from: Option<u64>,
        to: Option<u64>,
        after: Option<Position>,
    ) -> Self {
        slices.sort_by_key(|s| s.seq);
        if desc {
            slices.reverse();
        }
        Self {
            slices,
            slice_idx: 0,
            desc,
            from: from.unwrap_or(0),
            to: to.unwrap_or(u64::MAX),
            after,
            current: None,
            buffered: Vec::new(),
            segments_opened: 0,
            _marker: PhantomData,
        }
    }

    /// Number of segment files this scan actually opened so far.
    pub fn segments_opened(&self) -> u64 {
        self.segments_opened
    }

    /// True when the whole segment can be skipped without opening it.
    fn prune(&self, s: &SegmentSlice) -> bool {
        // time-range pruning: bounds never assume rows are time-ordered
        if s.max_ts < self.from || s.min_ts > self.to {
            return true;
        }
        // cursor pruning: whole segments on the consumed side of the cursor
        match self.after {
            Some(p) if !self.desc && s.seq < p.seq => true,
            Some(p) if self.desc && s.seq > p.seq => true,
            _ => false,
        }
    }

    fn in_range(&self, ts: u64) -> bool {
        ts >= self.from && ts <= self.to
    }

    fn past_cursor(&self, pos: Position) -> bool {
        match self.after {
            None => true,
            Some(p) => {
                if self.desc {
                    pos < p
                } else {
                    pos > p
                }
            }
        }
    }
}

impl<T: DeserializeOwned> PositionedScan<T> {
    /// Next matching row with its position, or `None` when exhausted.
    pub fn next_row(&mut self) -> Result<Option<(Position, T)>> {
        if self.desc {
            self.next_desc()
        } else {
            self.next_asc()
        }
    }

    fn next_asc(&mut self) -> Result<Option<(Position, T)>> {
        loop {
            if self.current.is_none() {
                let Some(slice) = self.next_slice()? else {
                    return Ok(None);
                };
                let reader = SegmentReader::open_bounded(&slice.path, slice.bound)?;
                self.current = Some((slice.seq, 0, reader));
            }
            let (seq, idx, reader) = self.current.as_mut().unwrap();
            match reader.next_record()? {
                Some((ts, payload)) => {
                    let pos = Position {
                        seq: *seq,
                        idx: *idx,
                    };
                    *idx += 1;
                    if self.in_range(ts) && self.past_cursor(pos) {
                        return Ok(Some((pos, bincode::deserialize(&payload)?)));
                    }
                }
                None => self.current = None,
            }
        }
    }

    fn next_desc(&mut self) -> Result<Option<(Position, T)>> {
        loop {
            if let Some((pos, _, payload)) = self.buffered.pop() {
                return Ok(Some((pos, bincode::deserialize(&payload)?)));
            }
            let Some(slice) = self.next_slice()? else {
                return Ok(None);
            };
            // segments only support forward reads (frames are forward-framed),
            // so buffer the matching rows of this one segment and drain the
            // buffer back-to-front
            let mut reader = SegmentReader::open_bounded(&slice.path, slice.bound)?;
            let mut idx = 0u64;
            while let Some((ts, payload)) = reader.next_record()? {
                let pos = Position {
                    seq: slice.seq,
                    idx,
                };
                idx += 1;
                if self.in_range(ts) && self.past_cursor(pos) {
                    self.buffered.push((pos, ts, payload));
                }
            }
        }
    }

    /// Advance to the next non-prunable slice; counts opened segments. A
    /// slice whose file vanished (retention ran between snapshot and scan
    /// for sealed segments is impossible — the snapshot holder keeps paths,
    /// not file handles) is surfaced as the underlying I/O error.
    fn next_slice(&mut self) -> Result<Option<SegmentSlice>> {
        while self.slice_idx < self.slices.len() {
            let s = self.slices[self.slice_idx].clone();
            self.slice_idx += 1;
            if self.prune(&s) {
                continue;
            }
            self.segments_opened += 1;
            return Ok(Some(s));
        }
        Ok(None)
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

    fn fill(t: &mut Table<Row>, n: u64) {
        for i in 0..n {
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
    }

    #[test]
    fn rolls_segments_scans_and_purges() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        fill(&mut t, 50);
        let rows: Vec<Row> = t.scan().unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 50);
        let files = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(SEGMENT_SUFFIX)
            })
            .count();
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
        // purged segments take their sidecars with them
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy().to_string();
            if let Some(seq) = name
                .strip_prefix(SEGMENT_PREFIX)
                .and_then(|s| s.strip_suffix(META_SUFFIX))
            {
                let seg = dir.path().join(format!("seg-{seq}.log"));
                assert!(seg.exists(), "orphaned sidecar {name}");
            }
        }
    }

    #[test]
    fn sidecar_meta_survives_reopen_and_rebuilds_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        fill(&mut t, 50);
        let slices_before = t.slices().unwrap();
        assert!(slices_before.len() > 1);
        drop(t);

        // delete one sidecar — open must rebuild identical bounds via skim
        let victim = meta_path(dir.path(), slices_before[0].seq);
        assert!(victim.exists());
        std::fs::remove_file(&victim).unwrap();
        let mut t2: Table<Row> = Table::open(dir.path(), 256).unwrap();
        let slices_after = t2.slices().unwrap();
        for (b, a) in slices_before.iter().zip(&slices_after) {
            assert_eq!((b.seq, b.min_ts, b.max_ts), (a.seq, a.min_ts, a.max_ts));
        }
        assert!(victim.exists(), "sidecar was not rebuilt");
    }

    #[test]
    fn positioned_scan_prunes_by_time_and_orders_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let mut t: Table<Row> = Table::open(dir.path(), 256).unwrap();
        fill(&mut t, 50);
        let slices = t.slices().unwrap();
        let total_segments = slices.len() as u64;

        // ascending, full range
        let mut scan: PositionedScan<Row> =
            PositionedScan::new(slices.clone(), false, None, None, None);
        let mut asc = Vec::new();
        while let Some((_, row)) = scan.next_row().unwrap() {
            asc.push(row.ts);
        }
        assert_eq!(asc, (0..50).collect::<Vec<_>>());
        assert_eq!(scan.segments_opened(), total_segments);

        // descending, full range
        let mut scan: PositionedScan<Row> =
            PositionedScan::new(slices.clone(), true, None, None, None);
        let mut desc = Vec::new();
        while let Some((_, row)) = scan.next_row().unwrap() {
            desc.push(row.ts);
        }
        assert_eq!(desc, (0..50).rev().collect::<Vec<_>>());

        // narrow time range: only segments overlapping [45, 49] are opened
        let mut scan: PositionedScan<Row> =
            PositionedScan::new(slices, true, Some(45), Some(49), None);
        let mut hits = Vec::new();
        while let Some((_, row)) = scan.next_row().unwrap() {
            hits.push(row.ts);
        }
        assert_eq!(hits, vec![49, 48, 47, 46, 45]);
        assert!(
            scan.segments_opened() < total_segments,
            "pruning opened all {total_segments} segments"
        );
    }
}
