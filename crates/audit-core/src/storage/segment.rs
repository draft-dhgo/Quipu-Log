use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Segment file header: magic, format version, hash-chain seed.
/// The version byte is the migration hook — readers reject formats they do not
/// understand instead of misparsing frames, so a future layout change can ship
/// with a converter keyed on this byte. The seed is the final chain value of
/// the previous segment (all-zero for the first segment of a table), which
/// links segments into one continuous tamper-evident chain.
pub const MAGIC: [u8; 4] = *b"ALOG";
pub const FORMAT_VERSION: u8 = 1;
pub const SEGMENT_HEADER: usize = MAGIC.len() + 1 + CHAIN_LEN;

/// Frame layout: u32 payload length, u32 crc32(payload), u64 record timestamp,
/// 32-byte chain hash = sha256(previous chain value || payload).
/// The timestamp lives in the header (not the payload) so retention can skim a
/// segment's time range without deserializing rows. The chain hash is the
/// tamper-evidence: CRC32 only catches accidental damage, but rewriting a
/// record in place (even with a recomputed CRC) breaks the chain of every
/// record after it, which [`verify_chain`] detects.
pub const FRAME_HEADER: usize = 4 + 4 + 8 + CHAIN_LEN;
/// Hard upper bound for a single record; protects recovery from interpreting
/// garbage as a multi-gigabyte length and trying to allocate it.
pub const MAX_RECORD: u32 = 64 * 1024 * 1024;

pub const CHAIN_LEN: usize = 32;
pub type ChainHash = [u8; CHAIN_LEN];

fn chain_next(prev: &ChainHash, payload: &[u8]) -> ChainHash {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(payload);
    h.finalize().into()
}

/// What [`skim`] learned about an existing segment file.
#[derive(Debug)]
pub struct Skim {
    /// Length of the valid prefix (header + whole, CRC-clean frames).
    pub valid_len: u64,
    pub max_timestamp: u64,
    /// Chain value stored in the last valid frame (the header seed if none).
    pub last_chain: ChainHash,
}

/// One append-only segment file, opened for writing.
pub struct Segment {
    path: PathBuf,
    writer: BufWriter<File>,
    len: u64,
    /// Highest record timestamp in the file; drives retention decisions.
    pub max_timestamp: u64,
    last_chain: ChainHash,
}

impl Segment {
    /// Open (creating if needed) a segment for appending. `seed` is the chain
    /// seed used only when the file is created; an existing file keeps its own.
    /// A torn tail from a crash is truncated back to the last whole record.
    pub fn open(path: &Path, seed: ChainHash) -> Result<Self> {
        let skimmed = skim(path)?;
        // append-style open: existing contents must survive (truncate(false))
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        match skimmed {
            Some(s) => {
                if file.metadata()?.len() > s.valid_len {
                    file.set_len(s.valid_len)?;
                }
                let mut writer = BufWriter::with_capacity(256 * 1024, file);
                writer.seek(SeekFrom::Start(s.valid_len))?;
                Ok(Self {
                    path: path.to_path_buf(),
                    writer,
                    len: s.valid_len,
                    max_timestamp: s.max_timestamp,
                    last_chain: s.last_chain,
                })
            }
            None => {
                // fresh file (or a header torn mid-write): write a new header
                file.set_len(0)?;
                let mut writer = BufWriter::with_capacity(256 * 1024, file);
                writer.write_all(&MAGIC)?;
                writer.write_all(&[FORMAT_VERSION])?;
                writer.write_all(&seed)?;
                Ok(Self {
                    path: path.to_path_buf(),
                    writer,
                    len: SEGMENT_HEADER as u64,
                    max_timestamp: 0,
                    last_chain: seed,
                })
            }
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len <= SEGMENT_HEADER as u64
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Chain value of the last appended record; seeds the next segment on roll.
    pub fn last_chain(&self) -> ChainHash {
        self.last_chain
    }

    /// Append one framed payload. Returns the offset the record starts at.
    /// Data lands in the buffer; call [`flush`]/[`sync`] per the durability policy.
    pub fn append(&mut self, payload: &[u8], timestamp: u64) -> Result<u64> {
        if payload.len() as u64 > MAX_RECORD as u64 {
            return Err(Error::Encode(format!(
                "record of {} bytes exceeds MAX_RECORD",
                payload.len()
            )));
        }
        let offset = self.len;
        let crc = crc32fast::hash(payload);
        let chain = chain_next(&self.last_chain, payload);
        self.writer
            .write_all(&(payload.len() as u32).to_le_bytes())?;
        self.writer.write_all(&crc.to_le_bytes())?;
        self.writer.write_all(&timestamp.to_le_bytes())?;
        self.writer.write_all(&chain)?;
        self.writer.write_all(payload)?;
        self.len += (FRAME_HEADER + payload.len()) as u64;
        self.max_timestamp = self.max_timestamp.max(timestamp);
        self.last_chain = chain;
        Ok(offset)
    }

    /// Push buffered bytes to the OS page cache.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Flush and fsync — survives power loss, costs a disk round-trip.
    pub fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }
}

fn read_header(reader: &mut impl Read, path: &Path) -> Result<(u8, ChainHash)> {
    let mut head = [0u8; SEGMENT_HEADER];
    reader.read_exact(&mut head)?;
    if head[0..4] != MAGIC {
        return Err(Error::Corrupt {
            segment: path.display().to_string(),
            offset: 0,
            reason: "bad magic (not an audit segment file)".into(),
        });
    }
    let version = head[4];
    if version != FORMAT_VERSION {
        return Err(Error::Corrupt {
            segment: path.display().to_string(),
            offset: 0,
            reason: format!(
                "unsupported segment format version {version} (this build reads version {FORMAT_VERSION})"
            ),
        });
    }
    let seed: ChainHash = head[5..SEGMENT_HEADER].try_into().unwrap();
    Ok((version, seed))
}

/// Skim an existing segment: validate the header and every frame (length +
/// crc), returning `None` for a missing/empty file. Payloads are read only for
/// the crc. Chain values are *recorded*, not verified — recovery must not
/// destroy tamper evidence, so verification is the separate [`verify_chain`].
pub fn skim(path: &Path) -> Result<Option<Skim>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let total = file.metadata()?.len();
    if total < SEGMENT_HEADER as u64 {
        // empty, or the header itself was torn mid-write: rewrite from scratch
        return Ok(None);
    }
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let (_, seed) = read_header(&mut reader, path)?;
    let mut valid = SEGMENT_HEADER as u64;
    let mut max_ts = 0u64;
    let mut last_chain = seed;
    let mut header = [0u8; FRAME_HEADER];
    let mut buf = Vec::new();
    loop {
        if total - valid < FRAME_HEADER as u64 {
            break;
        }
        reader.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let ts = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let chain: ChainHash = header[16..FRAME_HEADER].try_into().unwrap();
        if len > MAX_RECORD || total - valid - (FRAME_HEADER as u64) < len as u64 {
            break;
        }
        buf.resize(len as usize, 0);
        reader.read_exact(&mut buf)?;
        if crc32fast::hash(&buf) != crc {
            break;
        }
        valid += (FRAME_HEADER + len as usize) as u64;
        max_ts = max_ts.max(ts);
        last_chain = chain;
    }
    Ok(Some(Skim {
        valid_len: valid,
        max_timestamp: max_ts,
        last_chain,
    }))
}

/// Recompute the hash chain over every record and compare it to the stored
/// chain values. Returns `(seed, final chain)` so the caller can check
/// cross-segment linkage. A record whose CRC is fine but whose chain does not
/// match was modified in place after being written — that is tampering, not
/// bit rot.
pub fn verify_chain(path: &Path) -> Result<(ChainHash, ChainHash)> {
    let mut r = SegmentReader::open(path)?;
    let seed = r.seed;
    let mut expect = seed;
    loop {
        let offset = r.offset;
        match r.next_record_raw()? {
            None => return Ok((seed, expect)),
            Some((_, chain, payload)) => {
                expect = chain_next(&expect, &payload);
                if chain != expect {
                    return Err(Error::Corrupt {
                        segment: path.display().to_string(),
                        offset,
                        reason: "hash chain mismatch — record was modified after being written"
                            .into(),
                    });
                }
            }
        }
    }
}

/// Sequential reader over one segment's records.
pub struct SegmentReader {
    path: PathBuf,
    reader: BufReader<File>,
    offset: u64,
    end: u64,
    /// Chain seed from the file header.
    pub seed: ChainHash,
}

impl SegmentReader {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_bounded(path, u64::MAX)
    }

    /// Open with an upper read bound — a snapshot reader uses the length the
    /// writer had reached at snapshot time, so bytes appended concurrently
    /// afterwards (possibly half-flushed) are never touched.
    pub fn open_bounded(path: &Path, bound: u64) -> Result<Self> {
        let file = File::open(path)?;
        let end = file.metadata()?.len().min(bound);
        let mut reader = BufReader::with_capacity(256 * 1024, file);
        let seed = if end >= SEGMENT_HEADER as u64 {
            read_header(&mut reader, path)?.1
        } else {
            [0; CHAIN_LEN] // torn header: no readable records anyway
        };
        Ok(Self {
            path: path.to_path_buf(),
            reader,
            offset: SEGMENT_HEADER.min(end as usize) as u64,
            end,
            seed,
        })
    }

    /// Read the next record as (timestamp, payload), or `None` at end of segment.
    pub fn next_record(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        Ok(self
            .next_record_raw()?
            .map(|(ts, _, payload)| (ts, payload)))
    }

    fn next_record_raw(&mut self) -> Result<Option<(u64, ChainHash, Vec<u8>)>> {
        if self.end - self.offset < FRAME_HEADER as u64 {
            return Ok(None);
        }
        let mut header = [0u8; FRAME_HEADER];
        self.reader.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let ts = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let chain: ChainHash = header[16..FRAME_HEADER].try_into().unwrap();
        if len > MAX_RECORD || self.end - self.offset - (FRAME_HEADER as u64) < len as u64 {
            // torn tail: treat like EOF (writer-side recovery truncates it)
            return Ok(None);
        }
        let mut buf = vec![0u8; len as usize];
        self.reader.read_exact(&mut buf)?;
        if crc32fast::hash(&buf) != crc {
            return Err(Error::Corrupt {
                segment: self.path.display().to_string(),
                offset: self.offset,
                reason: "crc mismatch".into(),
            });
        }
        self.offset += (FRAME_HEADER + len as usize) as u64;
        Ok(Some((ts, chain, buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO: ChainHash = [0; CHAIN_LEN];

    #[test]
    fn append_read_and_recover_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0.log");
        {
            let mut seg = Segment::open(&path, ZERO).unwrap();
            seg.append(b"alpha", 1).unwrap();
            seg.append(b"beta", 2).unwrap();
            seg.sync().unwrap();
        }
        // simulate a crash mid-write: append garbage half-frame
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        }
        let mut seg = Segment::open(&path, ZERO).unwrap();
        assert_eq!(seg.max_timestamp, 2);
        seg.append(b"gamma", 3).unwrap();
        seg.sync().unwrap();

        let mut r = SegmentReader::open(&path).unwrap();
        let mut got = Vec::new();
        while let Some((ts, rec)) = r.next_record().unwrap() {
            got.push((ts, rec));
        }
        assert_eq!(
            got,
            vec![
                (1, b"alpha".to_vec()),
                (2, b"beta".to_vec()),
                (3, b"gamma".to_vec())
            ]
        );
        verify_chain(&path).unwrap();
    }

    #[test]
    fn in_place_edit_with_fixed_crc_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0.log");
        {
            let mut seg = Segment::open(&path, ZERO).unwrap();
            seg.append(b"original", 1).unwrap();
            seg.append(b"second", 2).unwrap();
            seg.sync().unwrap();
        }
        verify_chain(&path).unwrap();

        // attacker rewrites the first payload AND fixes up its crc
        let tampered = b"TAMPERED"; // same length as "original"
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start((SEGMENT_HEADER + 4) as u64))
                .unwrap();
            f.write_all(&crc32fast::hash(tampered).to_le_bytes())
                .unwrap();
            f.seek(SeekFrom::Start((SEGMENT_HEADER + FRAME_HEADER) as u64))
                .unwrap();
            f.write_all(tampered).unwrap();
        }

        // crc-level reads still pass...
        let mut r = SegmentReader::open(&path).unwrap();
        assert_eq!(r.next_record().unwrap().unwrap().1, tampered.to_vec());
        // ...but the chain verification catches the rewrite
        let err = verify_chain(&path).unwrap_err();
        assert!(err.to_string().contains("hash chain mismatch"), "{err}");
    }

    #[test]
    fn unsupported_format_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg-0.log");
        {
            let mut seg = Segment::open(&path, ZERO).unwrap();
            seg.append(b"x", 1).unwrap();
            seg.sync().unwrap();
        }
        {
            let mut f = OpenOptions::new().write(true).open(&path).unwrap();
            f.seek(SeekFrom::Start(4)).unwrap();
            f.write_all(&[99]).unwrap(); // future format version
        }
        let err = skim(&path).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported segment format version"),
            "{err}"
        );
    }
}
