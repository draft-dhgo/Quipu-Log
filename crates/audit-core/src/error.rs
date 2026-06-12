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
        }
    }
}

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
