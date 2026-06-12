use crate::error::{Error, Result};
use crate::model::{StoredValue, Value};
use crate::schema::FieldProtection;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Base64 (standard alphabet, padded) — implemented locally to avoid pulling a
/// dependency for two small functions.
mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let mut buf = Vec::with_capacity(s.len() / 4 * 3);
        let mut acc: u32 = 0;
        let mut bits = 0u8;
        for c in s.bytes() {
            if c == b'=' {
                break;
            }
            let v = ALPHABET.iter().position(|&a| a == c)? as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                buf.push((acc >> bits) as u8);
            }
        }
        Some(buf)
    }
}

/// Holds the key material used for field protection.
///
/// - RSA public key: enough to *write* encrypted fields; the private key is
///   only needed to read them back, so a log-producing service can run
///   without it.
/// - HMAC key: required to write *and* search [`FieldProtection::Hmac`]
///   fields ([`FieldProtection::Sha256`] needs no key). A keyed MAC is what
///   stops an attacker with disk access from recovering low-entropy values
///   (SSNs, phone numbers, ...) by brute-forcing the digest; without the key
///   the stored digests are useless. Use the same key across restarts or
///   historical values stop matching probes.
#[derive(Clone, Default)]
pub struct KeyRing {
    public: Option<RsaPublicKey>,
    private: Option<RsaPrivateKey>,
    mac: Option<Vec<u8>>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_pem(mut self, pem: &str) -> Result<Self> {
        self.public =
            Some(RsaPublicKey::from_public_key_pem(pem).map_err(|e| Error::Crypto(e.to_string()))?);
        Ok(self)
    }

    pub fn with_private_pem(mut self, pem: &str) -> Result<Self> {
        let private =
            RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| Error::Crypto(e.to_string()))?;
        if self.public.is_none() {
            self.public = Some(private.to_public_key());
        }
        self.private = Some(private);
        Ok(self)
    }

    /// Set the secret key for searchable-hash (HMAC-SHA-256) fields.
    pub fn with_hmac_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.mac = Some(key.as_ref().to_vec());
        self
    }

    /// Generate an in-memory RSA keypair and a random HMAC key (useful for
    /// tests and demos — production should load persistent keys).
    pub fn generate_ephemeral(bits: usize) -> Result<Self> {
        let private = RsaPrivateKey::new(&mut rand::thread_rng(), bits)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut mac = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut mac);
        Ok(Self {
            public: Some(private.to_public_key()),
            private: Some(private),
            mac: Some(mac),
        })
    }

    /// Keyed digest used for HMAC-protected fields and for search probes
    /// against them.
    pub fn hmac_hex(&self, data: &[u8]) -> Result<String> {
        let key = self.mac.as_ref().ok_or_else(|| {
            Error::Crypto("HMAC field declared but no HMAC key configured".into())
        })?;
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).map_err(|e| Error::Crypto(e.to_string()))?;
        mac.update(data);
        Ok(hex(&mac.finalize().into_bytes()))
    }

    /// Apply a schema-declared protection to a plain value.
    pub fn protect(&self, value: &Value, protection: FieldProtection) -> Result<StoredValue> {
        match protection {
            FieldProtection::None => Ok(StoredValue::Plain(value.clone())),
            FieldProtection::Sha256 => {
                Ok(StoredValue::Sha256(sha256_hex(&value.canonical_bytes())))
            }
            FieldProtection::Hmac => {
                Ok(StoredValue::Hmac(self.hmac_hex(&value.canonical_bytes())?))
            }
            FieldProtection::Rsa => {
                let key = self.public.as_ref().ok_or_else(|| {
                    Error::Crypto("RSA field declared but no public key configured".into())
                })?;
                // hybrid encryption: a fresh AES-256-GCM data key encrypts the
                // value in one authenticated pass (no per-chunk RSA, no chunk
                // reordering/truncation surface), then RSA-OAEP wraps the key
                let mut dek = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut dek);
                let mut nonce = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce);
                let cipher = Aes256Gcm::new_from_slice(&dek).expect("32-byte key");
                let ciphertext = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        value.canonical_bytes().as_slice(),
                    )
                    .map_err(|e| Error::Crypto(e.to_string()))?;
                let wrapped_key = key
                    .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), &dek)
                    .map_err(|e| Error::Crypto(e.to_string()))?;
                Ok(StoredValue::Rsa {
                    wrapped_key: b64::encode(&wrapped_key),
                    nonce: b64::encode(&nonce),
                    ciphertext: b64::encode(&ciphertext),
                })
            }
        }
    }

    /// Recover the canonical bytes of an RSA-protected value.
    pub fn decrypt(&self, stored: &StoredValue) -> Result<Vec<u8>> {
        let StoredValue::Rsa {
            wrapped_key,
            nonce,
            ciphertext,
        } = stored
        else {
            return Err(Error::Crypto("value is not RSA-encrypted".into()));
        };
        let key = self
            .private
            .as_ref()
            .ok_or_else(|| Error::Crypto("no private key configured for decryption".into()))?;
        let bad_b64 = || Error::Crypto("invalid base64".into());
        let dek = key
            .decrypt(
                Oaep::new::<Sha256>(),
                &b64::decode(wrapped_key).ok_or_else(bad_b64)?,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| Error::Crypto(e.to_string()))?;
        let nonce = b64::decode(nonce).ok_or_else(bad_b64)?;
        if nonce.len() != 12 {
            return Err(Error::Crypto("invalid nonce length".into()));
        }
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                b64::decode(ciphertext).ok_or_else(bad_b64)?.as_slice(),
            )
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        for data in [&b""[..], b"a", b"ab", b"abc", b"hello world!"] {
            assert_eq!(b64::decode(&b64::encode(data)).unwrap(), data);
        }
    }

    #[test]
    fn rsa_roundtrip() {
        let ring = KeyRing::generate_ephemeral(2048).unwrap();
        let v = Value::Text("secret-name".repeat(40)); // longer than one RSA block
        let stored = ring.protect(&v, FieldProtection::Rsa).unwrap();
        assert_eq!(ring.decrypt(&stored).unwrap(), v.canonical_bytes());
    }

    #[test]
    fn rsa_ciphertext_tampering_is_rejected() {
        let ring = KeyRing::generate_ephemeral(2048).unwrap();
        let stored = ring
            .protect(&Value::Text("secret".into()), FieldProtection::Rsa)
            .unwrap();
        let StoredValue::Rsa {
            wrapped_key,
            nonce,
            ciphertext,
        } = stored
        else {
            unreachable!()
        };
        let mut ct = b64::decode(&ciphertext).unwrap();
        ct[0] ^= 1;
        let tampered = StoredValue::Rsa {
            wrapped_key,
            nonce,
            ciphertext: b64::encode(&ct),
        };
        assert!(
            ring.decrypt(&tampered).is_err(),
            "GCM must reject a flipped bit"
        );
    }

    #[test]
    fn sha256_is_deterministic_and_keyless() {
        let ring = KeyRing::new(); // no keys at all
        let a = ring
            .protect(&Value::Text("x".into()), FieldProtection::Sha256)
            .unwrap();
        let b = ring
            .protect(&Value::Text("x".into()), FieldProtection::Sha256)
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_is_deterministic_per_key_only() {
        let ring = KeyRing::new().with_hmac_key(b"key-1");
        let a = ring
            .protect(&Value::Text("x".into()), FieldProtection::Hmac)
            .unwrap();
        let b = ring
            .protect(&Value::Text("x".into()), FieldProtection::Hmac)
            .unwrap();
        assert_eq!(a, b);

        let other = KeyRing::new().with_hmac_key(b"key-2");
        let c = other
            .protect(&Value::Text("x".into()), FieldProtection::Hmac)
            .unwrap();
        assert_ne!(a, c, "different keys must produce different digests");

        // and no key at all is an error, never a silent unsalted fallback
        assert!(KeyRing::new()
            .protect(&Value::Text("x".into()), FieldProtection::Hmac)
            .is_err());
    }
}
