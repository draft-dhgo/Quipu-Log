//! Opt-in local disk spool: where events go when the server cannot be reached.
//!
//! The reference availability pattern for a single-node server (see the
//! repository README's scope section): if the daemon is down or its queue is
//! full and the in-process retries are exhausted, the client appends the event
//! to a local file instead of dropping it, and replays the file once the server
//! is back. That moves the outage's cost from "audit records are lost" — a
//! compliance hole — to "audit records arrive late", which the server's
//! client-set `occurred_at` makes invisible in the final log.
//!
//! On-disk frame, mirroring `quipu-core`'s segment framing so the failure
//! behaviour is the same one the rest of the project already reasons about:
//!
//! ```text
//! [u32 LE payload length][u32 LE crc32(payload)][payload]
//! ```
//!
//! `payload` is the JSON of a [`SpoolRecord`] (the idempotency key plus the
//! serialized event body). A torn tail — a record half-written when the process
//! crashed — is detected by the length/crc check and truncated on the next
//! open, exactly as the store does it; whole records before it are intact.

use crate::transport::{SendOutcome, Transport};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// One spooled event: its stable idempotency key and the serialized request
/// body, kept together so a replay after a client restart still carries the
/// key that lets the server dedup it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpoolRecord {
    pub idempotency_key: String,
    /// The exact JSON bytes that go to `POST /v1/logs`.
    pub body: Vec<u8>,
}

/// Append-only file of events awaiting (re)delivery.
pub struct Spool {
    path: PathBuf,
    file: File,
}

/// Outcome of one [`Spool::drain`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Records the server accepted (new or recognised duplicate) and that are
    /// now removed from the spool.
    pub delivered: usize,
    /// Records the server permanently rejected (`Fatal`); dropped from the
    /// spool because replaying them cannot make progress. A non-zero count is
    /// worth surfacing — these are events that will never be recorded.
    pub discarded: usize,
    /// Records still failing transiently (`Retry`); kept for the next pass.
    pub kept: usize,
}

impl Spool {
    /// Open (creating if absent) the spool file at `path`. A torn tail left by
    /// a crash is truncated here before any append, so the file is always a
    /// run of whole records.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        let good_len = whole_records_len(&mut file)?;
        file.set_len(good_len)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self { path, file })
    }

    /// Append one record and fsync it. The fsync is the point of the spool:
    /// the event is only "safely buffered" once it has survived a power loss,
    /// so this trades latency for the durability guarantee the spool exists to
    /// provide.
    pub fn append(&mut self, record: &SpoolRecord) -> io::Result<()> {
        let payload = serde_json::to_vec(record)?;
        let len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "spool record too large"))?;
        let crc = crc32fast::hash(&payload);
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.extend_from_slice(&payload);
        self.file.write_all(&frame)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Number of records currently spooled (whole records on disk).
    pub fn len(&self) -> io::Result<usize> {
        Ok(self.read_all()?.len())
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Read every whole record, oldest first.
    pub fn read_all(&self) -> io::Result<Vec<SpoolRecord>> {
        let mut file = File::open(&self.path)?;
        read_records(&mut file)
    }

    /// Replay the spool through `transport`, oldest first, then rewrite the
    /// file to hold only the records still awaiting delivery.
    ///
    /// Delivery order is preserved and the pass stops replaying at the first
    /// `Retry`: events from one source are usually causally ordered, and
    /// skipping ahead past a still-unreachable server would only reorder them
    /// for no gain. Accepted/duplicate records before the stall are still
    /// removed. The rewrite is atomic (write a temp file, fsync, rename) so a
    /// crash mid-drain cannot lose the survivors.
    pub fn drain(&mut self, transport: &dyn Transport) -> io::Result<DrainReport> {
        let records = self.read_all()?;
        let mut report = DrainReport::default();
        let mut survivors: Vec<SpoolRecord> = Vec::new();
        let mut stalled = false;
        for record in records {
            if stalled {
                report.kept += 1;
                survivors.push(record);
                continue;
            }
            match transport.send(&record.body, &record.idempotency_key) {
                SendOutcome::Accepted | SendOutcome::Duplicate => report.delivered += 1,
                SendOutcome::Fatal { .. } => report.discarded += 1,
                SendOutcome::Retry { .. } => {
                    stalled = true;
                    report.kept += 1;
                    survivors.push(record);
                }
            }
        }
        self.rewrite(&survivors)?;
        Ok(report)
    }

    /// Atomically replace the spool contents with `records`.
    fn rewrite(&mut self, records: &[SpoolRecord]) -> io::Result<()> {
        let tmp = self.path.with_extension("spool.tmp");
        let mut out = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        for record in records {
            let payload = serde_json::to_vec(record)?;
            let len = u32::try_from(payload.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "spool record too large")
            })?;
            let crc = crc32fast::hash(&payload);
            out.write_all(&len.to_le_bytes())?;
            out.write_all(&crc.to_le_bytes())?;
            out.write_all(&payload)?;
        }
        out.sync_data()?;
        std::fs::rename(&tmp, &self.path)?;
        // reopen the live handle on the renamed file, positioned to append
        self.file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .open(&self.path)?;
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}

/// Read whole records from `file` (positioned at the start), stopping at EOF or
/// the first torn/corrupt frame — the same lenient tail handling the store uses
/// on recovery.
fn read_records(file: &mut File) -> io::Result<Vec<SpoolRecord>> {
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    loop {
        let mut header = [0u8; 8];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let mut payload = vec![0u8; len];
        if reader.read_exact(&mut payload).is_err() {
            break; // torn tail: stop, the whole records before it stand
        }
        if crc32fast::hash(&payload) != crc {
            break; // corrupt frame: treat like a torn tail
        }
        match serde_json::from_slice::<SpoolRecord>(&payload) {
            Ok(record) => out.push(record),
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Byte length of the leading run of whole, crc-valid records — where the file
/// should be truncated to drop a torn tail.
fn whole_records_len(file: &mut File) -> io::Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut good: u64 = 0;
    loop {
        let mut header = [0u8; 8];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let mut payload = vec![0u8; len];
        if reader.read_exact(&mut payload).is_err() {
            break;
        }
        if crc32fast::hash(&payload) != crc {
            break;
        }
        good += 8 + len as u64;
    }
    Ok(good)
}
