use crate::error::{Error, Result};
use crate::model::{StoredValue, Value};
use crate::schema::FieldProtection;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

/// Version id of one key in a [`KeyRing`]. Versions are operator-assigned,
/// must be `>= 1` (`0` is the sentinel for "keyless" digests) and only their
/// *ordering* matters: the highest version present is the **active** key —
/// the one every new write is protected with. Lower versions are retained
/// read-side material: they decrypt old values and probe old digests.
pub type KeyVersion = u32;

/// Sentinel [`KeyVersion`] for digests that involve no key at all
/// (SHA-256-protected fields and their index tokens).
pub const KEYLESS: KeyVersion = 0;

/// Base64 (standard alphabet, padded) — implemented locally to avoid pulling a
/// dependency for two small functions.
pub(crate) mod b64 {
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

/// One version slot of RSA material: either or both halves may be present
/// (a write-only deployment holds only public keys).
#[derive(Clone, Default)]
struct RsaPair {
    public: Option<RsaPublicKey>,
    private: Option<RsaPrivateKey>,
}

/// Holds the (versioned) key material used for field protection.
///
/// - RSA public key: enough to *write* encrypted fields; the private key is
///   only needed to read them back, so a log-producing service can run
///   without it.
/// - HMAC key: required to write *and* search [`FieldProtection::Hmac`]
///   fields ([`FieldProtection::Sha256`] needs no key). A keyed MAC is what
///   stops an attacker with disk access from recovering low-entropy values
///   (SSNs, phone numbers, ...) by brute-forcing the digest; without the key
///   the stored digests are useless.
///
/// **Rotation.** Each key carries a [`KeyVersion`]; the highest version of
/// each kind is *active* and protects every new write, and the version is
/// recorded on the stored value itself ([`StoredValue::Hmac`] /
/// [`StoredValue::Rsa`]) and on persisted index tokens. Older versions stay
/// in the ring as read-side material: [`decrypt`](Self::decrypt) picks the
/// private key the record names, and searches probe HMAC digests under every
/// held version, so rotating keys never silently severs old data. The
/// version-less builders (`with_hmac_key`, ...) install version 1 — a ring
/// that never rotates needs no version bookkeeping.
#[derive(Clone, Default)]
pub struct KeyRing {
    rsa: BTreeMap<KeyVersion, RsaPair>,
    macs: BTreeMap<KeyVersion, Vec<u8>>,
}

fn check_version(version: KeyVersion) -> Result<()> {
    if version == KEYLESS {
        return Err(Error::Crypto(
            "key version 0 is reserved for keyless digests — versions start at 1".into(),
        ));
    }
    Ok(())
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_pem(self, pem: &str) -> Result<Self> {
        self.with_public_pem_version(1, pem)
    }

    pub fn with_private_pem(self, pem: &str) -> Result<Self> {
        self.with_private_pem_version(1, pem)
    }

    /// Set the secret key for searchable-hash (HMAC-SHA-256) fields
    /// (version 1).
    pub fn with_hmac_key(self, key: impl AsRef<[u8]>) -> Self {
        self.with_hmac_key_version(1, key)
            .expect("version 1 is always valid")
    }

    /// Add the RSA public key of one key version.
    pub fn with_public_pem_version(mut self, version: KeyVersion, pem: &str) -> Result<Self> {
        check_version(version)?;
        self.rsa.entry(version).or_default().public =
            Some(RsaPublicKey::from_public_key_pem(pem).map_err(|e| Error::Crypto(e.to_string()))?);
        Ok(self)
    }

    /// Add the RSA private key of one key version (the matching public key is
    /// derived if it was not given separately).
    pub fn with_private_pem_version(mut self, version: KeyVersion, pem: &str) -> Result<Self> {
        check_version(version)?;
        let private =
            RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| Error::Crypto(e.to_string()))?;
        let pair = self.rsa.entry(version).or_default();
        if pair.public.is_none() {
            pair.public = Some(private.to_public_key());
        }
        pair.private = Some(private);
        Ok(self)
    }

    /// Add the HMAC key of one key version.
    pub fn with_hmac_key_version(
        mut self,
        version: KeyVersion,
        key: impl AsRef<[u8]>,
    ) -> Result<Self> {
        check_version(version)?;
        self.macs.insert(version, key.as_ref().to_vec());
        Ok(self)
    }

    /// Add a freshly generated in-memory RSA keypair under `version` (tests,
    /// demos and rotation drills — production should load persistent keys).
    pub fn with_generated_rsa(mut self, version: KeyVersion, bits: usize) -> Result<Self> {
        check_version(version)?;
        let private = RsaPrivateKey::new(&mut rand::thread_rng(), bits)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        self.rsa.insert(
            version,
            RsaPair {
                public: Some(private.to_public_key()),
                private: Some(private),
            },
        );
        Ok(self)
    }

    /// Add a freshly generated random HMAC key under `version`.
    pub fn with_generated_hmac(mut self, version: KeyVersion) -> Result<Self> {
        check_version(version)?;
        let mut mac = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut mac);
        self.macs.insert(version, mac);
        Ok(self)
    }

    /// Generate an in-memory RSA keypair and a random HMAC key, both version
    /// 1 (useful for tests and demos — production should load persistent keys).
    pub fn generate_ephemeral(bits: usize) -> Result<Self> {
        Self::new()
            .with_generated_rsa(1, bits)?
            .with_generated_hmac(1)
    }

    /// Version of the HMAC key new writes are digested with (the highest one).
    pub fn active_hmac_version(&self) -> Option<KeyVersion> {
        self.macs.keys().next_back().copied()
    }

    /// Version of the RSA key new writes are encrypted with (the highest one).
    pub fn active_rsa_version(&self) -> Option<KeyVersion> {
        self.rsa.keys().next_back().copied()
    }

    /// Every held HMAC key version, newest first — the probe order for
    /// multi-version digest matching (recent keys hit most often).
    pub fn hmac_versions(&self) -> Vec<KeyVersion> {
        self.macs.keys().rev().copied().collect()
    }

    /// Whether `version`'s RSA private key is held (re-key needs every
    /// version still referenced by stored values).
    pub fn has_rsa_private(&self, version: KeyVersion) -> bool {
        self.rsa.get(&version).is_some_and(|p| p.private.is_some())
    }

    fn mac_of(&self, version: KeyVersion) -> Result<&[u8]> {
        self.macs.get(&version).map(Vec::as_slice).ok_or_else(|| {
            Error::Crypto(format!("HMAC key version {version} is not in the key ring"))
        })
    }

    fn rsa_public_of(&self, version: KeyVersion) -> Result<&RsaPublicKey> {
        self.rsa
            .get(&version)
            .and_then(|p| p.public.as_ref())
            .ok_or_else(|| {
                Error::Crypto(format!("RSA public key version {version} is not in the key ring"))
            })
    }

    fn rsa_private_of(&self, version: KeyVersion) -> Result<&RsaPrivateKey> {
        self.rsa
            .get(&version)
            .and_then(|p| p.private.as_ref())
            .ok_or_else(|| {
                Error::Crypto(format!(
                    "RSA private key version {version} is not in the key ring"
                ))
            })
    }

    /// Keyed digest under the *active* HMAC key, used when writing
    /// HMAC-protected fields. Returns the version the digest was made with,
    /// which the caller persists next to the digest.
    pub fn hmac_hex(&self, data: &[u8]) -> Result<(KeyVersion, String)> {
        let version = self.active_hmac_version().ok_or_else(|| {
            Error::Crypto("HMAC field declared but no HMAC key configured".into())
        })?;
        Ok((version, self.hmac_hex_with(version, data)?))
    }

    /// Keyed digest under one specific HMAC key version — the probe side of
    /// multi-version search.
    pub fn hmac_hex_with(&self, version: KeyVersion, data: &[u8]) -> Result<String> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.mac_of(version)?)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        mac.update(data);
        Ok(hex(&mac.finalize().into_bytes()))
    }

    /// Digest of one blind-index token ([`crate::schema::FieldIndex`]) under
    /// the *active* key. Returns the key version used ([`KEYLESS`] for
    /// keyless protections), which the caller persists next to the digests.
    ///
    /// The input is domain-separated (`"idx:" + field + NUL + token`) so an
    /// index digest can never collide with — or be replayed as — the field's
    /// own stored digest. The digest function follows the field's protection:
    /// keyless protections (None/Sha256) use SHA-256, keyed ones (Hmac/Rsa)
    /// use the HMAC key, so the tokens of an encrypted field cannot be
    /// brute-forced offline any more than the field itself.
    pub fn index_token_digest(
        &self,
        field: &str,
        protection: FieldProtection,
        token: &str,
    ) -> Result<(KeyVersion, String)> {
        match protection {
            FieldProtection::None | FieldProtection::Sha256 => Ok((
                KEYLESS,
                self.index_token_digest_with(KEYLESS, field, protection, token)?,
            )),
            FieldProtection::Hmac | FieldProtection::Rsa => {
                let version = self.active_hmac_version().ok_or_else(|| {
                    Error::Crypto("HMAC field declared but no HMAC key configured".into())
                })?;
                Ok((
                    version,
                    self.index_token_digest_with(version, field, protection, token)?,
                ))
            }
        }
    }

    /// [`index_token_digest`](Self::index_token_digest) under one specific
    /// key version — the probe side of multi-version search. `version` is
    /// ignored for keyless protections.
    pub fn index_token_digest_with(
        &self,
        version: KeyVersion,
        field: &str,
        protection: FieldProtection,
        token: &str,
    ) -> Result<String> {
        let mut data = Vec::with_capacity(4 + field.len() + 1 + token.len());
        data.extend_from_slice(b"idx:");
        data.extend_from_slice(field.as_bytes());
        data.push(0);
        data.extend_from_slice(token.as_bytes());
        match protection {
            FieldProtection::None | FieldProtection::Sha256 => Ok(sha256_hex(&data)),
            FieldProtection::Hmac | FieldProtection::Rsa => self.hmac_hex_with(version, &data),
        }
    }

    /// Apply a schema-declared protection to a plain value, under the active
    /// key of the relevant kind. The key version is recorded on the stored
    /// value so reads outlive rotations.
    pub fn protect(&self, value: &Value, protection: FieldProtection) -> Result<StoredValue> {
        match protection {
            FieldProtection::None => Ok(StoredValue::Plain(value.clone())),
            FieldProtection::Sha256 => {
                Ok(StoredValue::Sha256(sha256_hex(&value.canonical_bytes())))
            }
            FieldProtection::Hmac => {
                let (key_version, digest) = self.hmac_hex(&value.canonical_bytes())?;
                Ok(StoredValue::Hmac { key_version, digest })
            }
            FieldProtection::Rsa => {
                let key_version = self.active_rsa_version().ok_or_else(|| {
                    Error::Crypto("RSA field declared but no public key configured".into())
                })?;
                let key = self.rsa_public_of(key_version)?;
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
                    key_version,
                    wrapped_key: b64::encode(&wrapped_key),
                    nonce: b64::encode(&nonce),
                    ciphertext: b64::encode(&ciphertext),
                })
            }
        }
    }

    /// Whether this ring can produce signatures (i.e. the *active* RSA
    /// version holds its private key). Write-only deployments (public keys
    /// only) cannot sign — checkpointing keys off this.
    pub fn can_sign(&self) -> bool {
        self.active_rsa_version()
            .is_some_and(|v| self.has_rsa_private(v))
    }

    /// RSA PKCS#1 v1.5 signature over SHA-256(data) with the active private
    /// key; returns the key version so verifiers can pick the matching public
    /// key after a rotation. PKCS#1 v1.5 (not PSS) because it is
    /// deterministic: re-signing identical checkpoint bytes yields identical
    /// signatures, which keeps externally anchored copies byte-comparable.
    pub fn sign(&self, data: &[u8]) -> Result<(KeyVersion, Vec<u8>)> {
        let version = self
            .active_rsa_version()
            .ok_or_else(|| Error::Crypto("no private key configured for signing".into()))?;
        let key = self.rsa_private_of(version)?;
        let digest = Sha256::digest(data);
        let sig = key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok((version, sig))
    }

    /// Verify a signature produced by [`sign`](Self::sign) under the named
    /// key version. Needs only that version's public key, so an auditor can
    /// verify without decryption capability.
    pub fn verify_signature(
        &self,
        key_version: KeyVersion,
        data: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let key = self.rsa_public_of(key_version)?;
        let digest = Sha256::digest(data);
        key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
            .map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Recover the canonical bytes of an RSA-protected value, with the
    /// private key of the version the value was written under.
    pub fn decrypt(&self, stored: &StoredValue) -> Result<Vec<u8>> {
        let StoredValue::Rsa {
            key_version,
            wrapped_key,
            nonce,
            ciphertext,
        } = stored
        else {
            return Err(Error::Crypto("value is not RSA-encrypted".into()));
        };
        let key = self.rsa_private_of(*key_version)?;
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

    /// Re-wrap the data key of an RSA-protected value under the *active*
    /// public key: the old version's private key unwraps the DEK, the active
    /// public key re-wraps it. Nonce and ciphertext are untouched (the DEK
    /// itself never changed), so this is cheap and cannot corrupt the
    /// payload. Values already at the active version pass through unchanged.
    pub fn rewrap(&self, stored: &StoredValue) -> Result<StoredValue> {
        let StoredValue::Rsa {
            key_version,
            wrapped_key,
            nonce,
            ciphertext,
        } = stored
        else {
            return Err(Error::Crypto("value is not RSA-encrypted".into()));
        };
        let active = self
            .active_rsa_version()
            .ok_or_else(|| Error::Crypto("no RSA key configured to re-wrap to".into()))?;
        if *key_version == active {
            return Ok(stored.clone());
        }
        let old = self.rsa_private_of(*key_version)?;
        let bad_b64 = || Error::Crypto("invalid base64".into());
        let dek = old
            .decrypt(
                Oaep::new::<Sha256>(),
                &b64::decode(wrapped_key).ok_or_else(bad_b64)?,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let wrapped = self
            .rsa_public_of(active)?
            .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), &dek)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(StoredValue::Rsa {
            key_version: active,
            wrapped_key: b64::encode(&wrapped),
            nonce: nonce.clone(),
            ciphertext: ciphertext.clone(),
        })
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub(crate) fn hex(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
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
            key_version,
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
            key_version,
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
