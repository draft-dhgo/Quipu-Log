use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// A record failed its CRC or length check while reading a segment.
    Corrupt {
        segment: String,
        offset: u64,
        reason: String,
    },
    Encode(String),
    Crypto(String),
    /// Schema/registry misuse: unknown type, missing field, kind mismatch, ...
    Schema(String),
    NotFound(String),
    /// Another process already holds the store root open.
    Locked(String),
    /// A pagination cursor failed to decode, or was issued under different
    /// query semantics (e.g. the opposite sort order). Client error.
    InvalidCursor(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Corrupt {
                segment,
                offset,
                reason,
            } => {
                write!(
                    f,
                    "corrupt record in {segment} at offset {offset}: {reason}"
                )
            }
            Error::Encode(m) => write!(f, "encode/decode error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Schema(m) => write!(f, "schema error: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::Locked(root) => write!(
                f,
                "store root '{root}' is locked by another process (the store is single-process)"
            ),
            Error::InvalidCursor(m) => write!(f, "invalid cursor: {m}"),
        }
    }
}

impl Error {
    /// True when the underlying cause is an out-of-space condition (ENOSPC,
    /// surfaced as [`std::io::ErrorKind::StorageFull`] or raw OS error 28 on
    /// Linux/macOS).
    ///
    /// Disk-full is a *persistent* failure: unlike a transient I/O hiccup,
    /// retrying the same write is pointless until space is actually freed.
    /// Callers should skip retry/backoff loops for these and go straight to
    /// their fallback path.
    pub fn is_storage_full(&self) -> bool {
        match self {
            Error::Io(e) => io_is_storage_full(e),
            _ => false,
        }
    }
}

/// ENOSPC detection on a raw [`std::io::Error`]. Both checks are needed:
/// `ErrorKind::StorageFull` covers errors std already classified, the raw
/// code covers errors wrapped from syscalls std maps to `Other`/`Uncategorized`
/// on some platforms.
pub fn io_is_storage_full(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::StorageFull || e.raw_os_error() == Some(ENOSPC)
}

/// POSIX `ENOSPC` ("no space left on device") — 28 on Linux and macOS.
const ENOSPC: i32 = 28;

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Error::Encode(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn classifies_enospc_by_raw_os_error() {
        let e = Error::Io(std::io::Error::from_raw_os_error(ENOSPC));
        assert!(e.is_storage_full());
    }

    #[test]
    fn classifies_enospc_by_error_kind() {
        // injected error with the right kind but no raw OS code — the path a
        // wrapped/synthetic StorageFull error takes
        let e = Error::Io(std::io::Error::new(ErrorKind::StorageFull, "disk full"));
        assert!(e.is_storage_full());
    }

    #[test]
    fn other_errors_are_not_storage_full() {
        for e in [
            Error::Io(std::io::Error::from_raw_os_error(13)), // EACCES
            Error::Io(std::io::Error::new(ErrorKind::PermissionDenied, "nope")),
            Error::Schema("x".into()),
            Error::NotFound("x".into()),
            Error::Encode("x".into()),
        ] {
            assert!(!e.is_storage_full(), "{e} misclassified as storage-full");
        }
    }
}
