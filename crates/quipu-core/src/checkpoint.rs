//! Signed integrity checkpoints.
//!
//! The per-record hash chain proves that retained records were not edited in
//! place and that no retained segment was swapped out. It cannot expose a
//! *full rewrite*: an insider with disk access can delete every segment and
//! replay a self-consistent chain from scratch, and nothing inside the store
//! remains to contradict it. A checkpoint pins (segment seq, record count,
//! chain head) under an RSA signature in a separate append-only file, and the
//! anchor hook ([`crate::StoreConfig::anchor`]) lets the operator export each
//! checkpoint to an external trust domain the insider cannot reach (another
//! host, a ticket system, a transparency log). A rewritten chain cannot
//! reproduce the checkpointed head without the original records, and a forged
//! checkpoint cannot be signed without the private key.

use crate::crypto::{self, KeyRing};
use crate::error::{Error, Result};
use crate::storage::ChainHash;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "checkpoints.log";
const WIRE_VERSION: u8 = 1;
/// Domain separation: these signatures must never be confusable with any
/// other RSA signature made by the same key.
const SIGNING_DOMAIN: &[u8] = b"quipu-checkpoint-v1\0";

/// One signed integrity checkpoint of the audit-log chain. See the module
/// docs for the threat it addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// UTC micros at signing time.
    pub created_at: u64,
    /// Sequence number of the logs segment that was active at checkpoint time.
    pub segment_seq: u64,
    /// Log records on disk at checkpoint time (decreases after retention).
    pub record_count: u64,
    /// Chain value of the newest log record at checkpoint time.
    pub chain_head: ChainHash,
    /// [`crate::crypto::KeyVersion`] of the RSA key that signed this
    /// checkpoint — after a rotation, old checkpoints still verify against
    /// the retained public key of their own version.
    pub key_version: u32,
    /// RSA PKCS#1 v1.5 / SHA-256 signature over the fields above.
    pub signature: Vec<u8>,
}

impl Checkpoint {
    /// Sign a new checkpoint. Fails if the [`KeyRing`] holds no private key —
    /// callers gate on [`KeyRing::can_sign`] to skip instead.
    pub(crate) fn sign(
        keys: &KeyRing,
        created_at: u64,
        segment_seq: u64,
        record_count: u64,
        chain_head: ChainHash,
    ) -> Result<Self> {
        let (key_version, signature) = keys.sign(&signing_bytes(
            created_at,
            segment_seq,
            record_count,
            &chain_head,
        ))?;
        Ok(Self {
            created_at,
            segment_seq,
            record_count,
            chain_head,
            key_version,
            signature,
        })
    }

    /// Verify the signature with the ring's public key.
    pub fn verify(&self, keys: &KeyRing) -> Result<()> {
        keys.verify_signature(
            self.key_version,
            &signing_bytes(
                self.created_at,
                self.segment_seq,
                self.record_count,
                &self.chain_head,
            ),
            &self.signature,
        )
        .map_err(|e| Error::Crypto(format!("checkpoint signature invalid: {e}")))
    }

    /// Hex form of the chain head — the value to hand to external anchors.
    pub fn chain_head_hex(&self) -> String {
        crypto::hex(&self.chain_head)
    }
}

fn signing_bytes(
    created_at: u64,
    segment_seq: u64,
    record_count: u64,
    chain_head: &ChainHash,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + 24 + chain_head.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(&created_at.to_le_bytes());
    out.extend_from_slice(&segment_seq.to_le_bytes());
    out.extend_from_slice(&record_count.to_le_bytes());
    out.extend_from_slice(chain_head);
    out
}

/// On-disk line format: one JSON object per line, hex/base64 for the binary
/// fields so the file stays human-inspectable (it is the artifact operators
/// compare against external anchors).
#[derive(Serialize, Deserialize)]
struct Wire {
    v: u8,
    created_at: u64,
    segment_seq: u64,
    record_count: u64,
    chain_head: String,
    /// Signing-key version. Defaults to 1 for lines written before key
    /// rotation existed (JSON is self-describing, so this is additive).
    #[serde(default = "default_key_version")]
    key_version: u32,
    signature: String,
}

fn default_key_version() -> u32 {
    1
}

/// The append-only checkpoint file at the store root. Deliberately *not* a
/// segment [`Table`](crate::storage::Table): checkpoints are the external
/// reference for the segment chain and must not depend on the format they
/// vouch for, and segment files stay byte-identical to stores that never
/// checkpoint.
pub(crate) struct CheckpointLog {
    path: PathBuf,
}

impl CheckpointLog {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            path: root.join(FILE_NAME),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Append one checkpoint and fsync. Checkpoints are rare (segment seals,
    /// retention runs), so unconditional durability is cheap here — and a
    /// checkpoint that claims a head must not itself be lost to a crash.
    pub(crate) fn append(&self, cp: &Checkpoint) -> Result<()> {
        let wire = Wire {
            v: WIRE_VERSION,
            created_at: cp.created_at,
            segment_seq: cp.segment_seq,
            record_count: cp.record_count,
            chain_head: crypto::hex(&cp.chain_head),
            key_version: cp.key_version,
            signature: crypto::b64::encode(&cp.signature),
        };
        let mut line = serde_json::to_string(&wire).map_err(|e| Error::Encode(e.to_string()))?;
        line.push('\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// Read every checkpoint, oldest first. A missing file means "never
    /// checkpointed" (write-only configurations). A torn *last* line is a
    /// crash mid-append and is skipped; a malformed earlier line is
    /// corruption and fails.
    pub(crate) fn read_all(&self) -> Result<Vec<Checkpoint>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut out = Vec::with_capacity(lines.len());
        for (i, line) in lines.iter().enumerate() {
            match parse_line(line) {
                Some(cp) => out.push(cp),
                None if i == lines.len() - 1 => break,
                None => {
                    return Err(Error::Corrupt {
                        segment: self.path.display().to_string(),
                        offset: i as u64,
                        reason: "unreadable checkpoint line".into(),
                    });
                }
            }
        }
        Ok(out)
    }
}

fn parse_line(line: &str) -> Option<Checkpoint> {
    let wire: Wire = serde_json::from_str(line).ok()?;
    if wire.v != WIRE_VERSION {
        return None;
    }
    let head: ChainHash = crypto::hex_decode(&wire.chain_head)?.try_into().ok()?;
    Some(Checkpoint {
        created_at: wire.created_at,
        segment_seq: wire.segment_seq,
        record_count: wire.record_count,
        chain_head: head,
        key_version: wire.key_version,
        signature: crypto::b64::decode(&wire.signature)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_torn_tail_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let log = CheckpointLog::new(dir.path());
        assert!(log.read_all().unwrap().is_empty(), "missing file is empty");

        let keys = KeyRing::generate_ephemeral(2048).unwrap();
        let cp = Checkpoint::sign(&keys, 1, 2, 3, [7; 32]).unwrap();
        log.append(&cp).unwrap();
        // simulate a crash mid-append of the next checkpoint
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap();
        f.write_all(b"{\"v\":1,\"created_at\":9").unwrap();
        drop(f);

        let read = log.read_all().unwrap();
        assert_eq!(read, vec![cp.clone()]);
        read[0].verify(&keys).unwrap();

        // a tampered field breaks the signature
        let mut bad = cp;
        bad.record_count += 1;
        assert!(bad.verify(&keys).is_err());
    }
}
