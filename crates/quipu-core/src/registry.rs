use crate::crypto::{sha256_hex, KeyRing};
use crate::error::{Error, Result};
use crate::id::Uid;
use crate::model::{StoredValue, Value, ValueKind};
use crate::query::MatchMode;
use crate::schema::{FieldDef, FieldIndex, FieldProtection, TypeSchema};
use crate::storage::Table;
use crate::tokens;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

/// Caller-side description of an entity (actor or target) to register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityInput {
    /// Stable external identifier (your user id, document id, ...).
    pub entity_id: String,
    pub fields: BTreeMap<String, Value>,
}

impl EntityInput {
    pub fn new(entity_id: impl Into<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            fields: BTreeMap::new(),
        }
    }

    pub fn field(mut self, name: &str, value: Value) -> Self {
        self.fields.insert(name.to_string(), value);
        self
    }

    pub fn text(self, name: &str, value: impl Into<String>) -> Self {
        self.field(name, Value::Text(value.into()))
    }
}

/// One immutable version of an entity. Audit-log targets reference a version
/// `uid`, never the entity itself — that is what freezes "the values at record
/// time" into history even when the entity is later renamed or deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRecord {
    pub uid: Uid,
    pub entity_id: String,
    pub entity_type: String,
    pub version: u32,
    pub recorded_at: u64,
    pub deleted: bool,
    pub fields: BTreeMap<String, StoredValue>,
    /// Blind-index token digests per field ([`crate::schema::FieldIndex`]),
    /// computed from the plaintext at write time. Persisting them here is
    /// what keeps protected fields prefix/substring-searchable across
    /// restarts — the plaintext is not on disk to re-derive them from.
    #[serde(default)]
    pub tokens: BTreeMap<String, FieldTokens>,
}

/// The persisted blind-index token set of one field of one record version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldTokens {
    /// [`crate::crypto::KeyVersion`] of the HMAC key the digests were made
    /// with ([`crate::crypto::KEYLESS`] for keyless protections). Recorded so
    /// probes — and the re-key tool — know which key these digests answer to.
    pub key_version: u32,
    pub digests: Vec<String>,
}

/// The in-memory, queryable side of one type's registry: version maps, search
/// indexes and plaintext caches. Cloneable so queries can run on a snapshot
/// without holding up the writer ([`crate::store::ReadSnapshot`]); registries
/// are tiny next to logs, so the clone is cheap.
#[derive(Clone)]
pub(crate) struct RegistryIndex {
    pub(crate) schema: TypeSchema,
    /// entity_id -> uids of all its versions, oldest first.
    versions: HashMap<String, Vec<Uid>>,
    /// every version ever written, by uid.
    by_uid: HashMap<Uid, RegistryRecord>,
    /// indexed field -> search key -> entity_ids that carried that value in
    /// *any* version. Keys are canonical bytes (plain fields) or the digest
    /// hex (hashed fields), so historical values stay searchable forever.
    index: HashMap<String, HashMap<Vec<u8>, HashSet<String>>>,
    /// field -> token digest -> entity_ids that carried that token in *any*
    /// version (the per-version token sets live on the records themselves).
    /// Posting lists for [`FieldIndex`] searches, rebuilt from
    /// [`RegistryRecord::tokens`] on open.
    token_index: HashMap<String, HashMap<String, HashSet<String>>>,
    /// (version uid, field) -> plaintext canonical bytes, memory-only.
    /// Two sources: values *written by this process* for protected fields
    /// (held at upsert time, before protection is applied) and RSA values
    /// decrypted on demand during Contains searches. This is what makes
    /// LIKE-style search possible on protected fields — with the caveat that
    /// for one-way hashed fields it only covers versions written since this
    /// process started (the plaintext is not on disk, by design).
    held: HashMap<(Uid, String), Vec<u8>>,
    /// Whether `held` may be populated at all
    /// ([`crate::StoreConfig::plaintext_cache`]). When off, Contains search
    /// on protected fields is rejected instead of silently keeping
    /// plaintexts in memory.
    cache_plaintexts: bool,
}

impl RegistryIndex {
    fn new(schema: TypeSchema, cache_plaintexts: bool) -> Self {
        Self {
            schema,
            versions: HashMap::new(),
            by_uid: HashMap::new(),
            index: HashMap::new(),
            token_index: HashMap::new(),
            held: HashMap::new(),
            cache_plaintexts,
        }
    }

    fn absorb(&mut self, rec: RegistryRecord) {
        for (name, stored) in &rec.fields {
            let indexed = self.schema.field(name).map(|f| f.indexed).unwrap_or(false);
            if !indexed {
                continue;
            }
            if let Some(key) = index_key(stored) {
                self.index
                    .entry(name.clone())
                    .or_default()
                    .entry(key)
                    .or_default()
                    .insert(rec.entity_id.clone());
            }
        }
        for (field, tokens) in &rec.tokens {
            let posting = self.token_index.entry(field.clone()).or_default();
            for d in &tokens.digests {
                posting
                    .entry(d.clone())
                    .or_default()
                    .insert(rec.entity_id.clone());
            }
        }
        self.versions
            .entry(rec.entity_id.clone())
            .or_default()
            .push(rec.uid);
        self.by_uid.insert(rec.uid, rec);
    }

    /// Find entity_ids whose given field matched `probe` in any version
    /// (`include_past = true`) or in their latest version only. Protected
    /// fields need the same `keys` the values were written with.
    pub(crate) fn search(
        &mut self,
        field: &str,
        probe: &Value,
        include_past: bool,
        mode: MatchMode,
        keys: &KeyRing,
    ) -> Result<Vec<String>> {
        let def = self
            .schema
            .field(field)
            .ok_or_else(|| Error::Schema(format!("unknown field '{field}'")))?
            .clone();
        match mode {
            MatchMode::Exact => {
                if !def.indexed {
                    return Err(Error::Schema(format!("field '{field}' is not indexed")));
                }
                // one probe key per held key version: a digest only ever
                // matches records written under the same key, so OR-ing the
                // per-version lookups is exact (keyless protections probe once)
                let probe_keys: Vec<Vec<u8>> = match def.protection {
                    FieldProtection::None => vec![probe.canonical_bytes()],
                    FieldProtection::Sha256 => {
                        vec![sha256_hex(&probe.canonical_bytes()).into_bytes()]
                    }
                    FieldProtection::Hmac => {
                        let versions = keys.hmac_versions();
                        if versions.is_empty() {
                            return Err(Error::Crypto(
                                "HMAC field declared but no HMAC key configured".into(),
                            ));
                        }
                        versions
                            .into_iter()
                            .map(|v| {
                                Ok(keys.hmac_hex_with(v, &probe.canonical_bytes())?.into_bytes())
                            })
                            .collect::<Result<_>>()?
                    }
                    FieldProtection::Rsa => unreachable!("rsa fields are rejected at open()"),
                };
                let mut hits: HashSet<String> = HashSet::new();
                for key in &probe_keys {
                    if let Some(ids) = self.index.get(field).and_then(|m| m.get(key)) {
                        hits.extend(ids.iter().cloned());
                    }
                }
                let mut out: Vec<String> = if include_past {
                    hits.into_iter().collect()
                } else {
                    hits.into_iter()
                        .filter(|id| {
                            self.latest(id).is_some_and(|rec| {
                                !rec.deleted
                                    && rec
                                        .fields
                                        .get(field)
                                        .and_then(index_key)
                                        .is_some_and(|k| probe_keys.contains(&k))
                            })
                        })
                        .collect()
                };
                out.sort();
                Ok(out)
            }
            MatchMode::ExactCi => {
                let norm = tokens::normalize(&probe_text(probe));
                if def.search == FieldIndex::Exact {
                    return self.token_match(&def, &[norm], include_past, keys);
                }
                self.scan_matching(field, &def, include_past, keys, None, |hay| {
                    tokens::normalize(&String::from_utf8_lossy(hay)) == norm
                })
            }
            MatchMode::Prefix => {
                let norm = tokens::normalize(&probe_text(probe));
                if let FieldIndex::Prefix(n) = def.search {
                    let plen = norm.chars().count();
                    if (1..=n).contains(&plen) {
                        return self.token_match(&def, &[norm], include_past, keys);
                    }
                    // probe longer than the declared prefix depth: fall back
                    // to the plaintext scan below (plain fields always work;
                    // protected fields need the plaintext cache)
                }
                self.scan_matching(field, &def, include_past, keys, None, |hay| {
                    tokens::normalize(&String::from_utf8_lossy(hay)).starts_with(&norm)
                })
            }
            MatchMode::Contains => {
                if let FieldIndex::Ngram(n) = def.search {
                    if let Some(toks) = tokens::ngram_probe_tokens(&probe_text(probe), n) {
                        let candidates = self.token_match(&def, &toks, include_past, keys)?;
                        let norm = tokens::normalize(&probe_text(probe));
                        return match def.protection {
                            // plaintext at hand: confirm the real substring
                            // (case-insensitive — the index is normalized)
                            FieldProtection::None => self.scan_matching(
                                field,
                                &def,
                                include_past,
                                keys,
                                Some(&candidates),
                                |hay| {
                                    tokens::normalize(&String::from_utf8_lossy(hay)).contains(&norm)
                                },
                            ),
                            // decryptable: only candidates are decrypted, so
                            // the index turns the full decrypt-scan into a
                            // candidate-scan (cache requirement unchanged —
                            // scan_matching enforces it)
                            FieldProtection::Rsa => self.scan_matching(
                                field,
                                &def,
                                include_past,
                                keys,
                                Some(&candidates),
                                |hay| {
                                    tokens::normalize(&String::from_utf8_lossy(hay)).contains(&norm)
                                },
                            ),
                            // one-way hashed: nothing to verify against — the
                            // candidates are the result (may contain false
                            // positives, see FieldIndex::Ngram)
                            FieldProtection::Sha256 | FieldProtection::Hmac => Ok(candidates),
                        };
                    }
                    // probe shorter than n: the index cannot help, fall back
                }
                // full scan over the in-memory registry (no index needed)
                let pat = probe.canonical_bytes();
                self.scan_matching(field, &def, include_past, keys, None, |hay| {
                    contains(hay, &pat)
                })
            }
        }
    }

    /// Token-index match of normalized probe tokens, across every held key
    /// version. For keyed fields the digests are recomputed per HMAC key
    /// version and the per-version candidate sets are OR-ed: a record's
    /// tokens were all digested under one key, so a digest only matches
    /// records written under that key and the union is exact. Keyless fields
    /// probe once.
    fn token_match(
        &self,
        def: &FieldDef,
        probe_tokens: &[String],
        include_past: bool,
        keys: &KeyRing,
    ) -> Result<Vec<String>> {
        let digest_sets: Vec<Vec<String>> = match def.protection {
            FieldProtection::None | FieldProtection::Sha256 => vec![probe_tokens
                .iter()
                .map(|t| {
                    keys.index_token_digest_with(crate::crypto::KEYLESS, &def.name, def.protection, t)
                })
                .collect::<Result<_>>()?],
            FieldProtection::Hmac | FieldProtection::Rsa => {
                let versions = keys.hmac_versions();
                if versions.is_empty() {
                    return Err(Error::Crypto(
                        "HMAC field declared but no HMAC key configured".into(),
                    ));
                }
                versions
                    .into_iter()
                    .map(|v| {
                        probe_tokens
                            .iter()
                            .map(|t| keys.index_token_digest_with(v, &def.name, def.protection, t))
                            .collect::<Result<Vec<_>>>()
                    })
                    .collect::<Result<_>>()?
            }
        };
        let mut out: Vec<String> = Vec::new();
        for digests in &digest_sets {
            out.extend(self.token_candidates(&def.name, digests, include_past));
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Entities with a version whose blind-index token set covers *all*
    /// `digests` (the per-record check keeps tokens of different versions
    /// from being combined into a phantom match). `include_past = false`
    /// restricts to the latest, non-deleted version.
    fn token_candidates(&self, field: &str, digests: &[String], include_past: bool) -> Vec<String> {
        let Some(posting) = self.token_index.get(field) else {
            return Vec::new();
        };
        let mut iter = digests.iter();
        let Some(first) = iter.next() else {
            return Vec::new();
        };
        let Some(mut ids) = posting.get(first).cloned() else {
            return Vec::new();
        };
        for d in iter {
            match posting.get(d) {
                Some(s) => ids.retain(|id| s.contains(id)),
                None => return Vec::new(),
            }
        }
        let carries_all = |uid: &Uid| {
            self.by_uid[uid]
                .tokens
                .get(field)
                .is_some_and(|t| digests.iter().all(|d| t.digests.contains(d)))
        };
        let mut out: Vec<String> = ids
            .into_iter()
            .filter(|id| {
                let uids = self.versions.get(id).map(Vec::as_slice).unwrap_or(&[]);
                if include_past {
                    uids.iter().any(carries_all)
                } else {
                    uids.last()
                        .is_some_and(|u| !self.by_uid[u].deleted && carries_all(u))
                }
            })
            .collect();
        out.sort();
        out
    }

    /// Scan plaintexts (all of them, or only the versions of `restrict`ed
    /// entity_ids) and keep entities where `pred` accepts some version.
    fn scan_matching(
        &mut self,
        field: &str,
        def: &FieldDef,
        include_past: bool,
        keys: &KeyRing,
        restrict: Option<&[String]>,
        pred: impl Fn(&[u8]) -> bool,
    ) -> Result<Vec<String>> {
        if def.protection != FieldProtection::None && !self.cache_plaintexts {
            return Err(Error::Schema(format!(
                "field '{field}' is protected and the plaintext cache is disabled — \
                 enable StoreConfig::plaintext_cache, declare a FieldIndex on the \
                 field, or use exact match"
            )));
        }
        let latest_alive =
            |versions: &Vec<Uid>| versions.last().copied().filter(|u| !self.by_uid[u].deleted);
        let uids: Vec<Uid> = match restrict {
            Some(ids) => ids
                .iter()
                .filter_map(|id| self.versions.get(id))
                .flat_map(|v| {
                    if include_past {
                        v.clone()
                    } else {
                        latest_alive(v).into_iter().collect()
                    }
                })
                .collect(),
            None if include_past => self.by_uid.keys().copied().collect(),
            None => self.versions.values().filter_map(latest_alive).collect(),
        };
        let mut hits = HashSet::new();
        for uid in uids {
            if let Some(hay) = self.plaintext_of(uid, field, keys)? {
                if pred(&hay) {
                    hits.insert(self.by_uid[&uid].entity_id.clone());
                }
            }
        }
        let mut out: Vec<String> = hits.into_iter().collect();
        out.sort();
        Ok(out)
    }

    /// Plaintext canonical bytes of one version's field, if recoverable:
    /// plain values directly, RSA values decrypted once and cached, hashed
    /// values only if this process held the plaintext at write time.
    fn plaintext_of(&mut self, uid: Uid, field: &str, keys: &KeyRing) -> Result<Option<Vec<u8>>> {
        let Some(stored) = self.by_uid[&uid].fields.get(field) else {
            return Ok(None);
        };
        match stored {
            StoredValue::Plain(v) => Ok(Some(v.canonical_bytes())),
            StoredValue::Sha256(_) | StoredValue::Hmac { .. } => {
                Ok(self.held.get(&(uid, field.to_string())).cloned())
            }
            StoredValue::Rsa { .. } => {
                if let Some(pt) = self.held.get(&(uid, field.to_string())) {
                    return Ok(Some(pt.clone()));
                }
                let pt = keys.decrypt(stored)?;
                self.held.insert((uid, field.to_string()), pt.clone());
                Ok(Some(pt))
            }
        }
    }

    pub(crate) fn latest_uid(&self, entity_id: &str) -> Option<Uid> {
        self.versions.get(entity_id).and_then(|v| v.last().copied())
    }

    pub(crate) fn latest(&self, entity_id: &str) -> Option<&RegistryRecord> {
        self.latest_uid(entity_id)
            .and_then(|uid| self.by_uid.get(&uid))
    }

    pub(crate) fn version(&self, uid: &Uid) -> Option<&RegistryRecord> {
        self.by_uid.get(uid)
    }

    pub(crate) fn all_version_uids(&self, entity_id: &str) -> &[Uid] {
        self.versions
            .get(entity_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub(crate) fn entity_ids(&self) -> impl Iterator<Item = &String> {
        self.versions.keys()
    }
}

/// The registry "table" for one entity type: an append-only version log on
/// disk plus the in-memory [`RegistryIndex`] rebuilt on open.
pub struct TypeRegistry {
    table: Table<RegistryRecord>,
    pub(crate) idx: RegistryIndex,
    /// entity_id -> fingerprint of the latest version's plain field values;
    /// lets upsert skip writing a new version when nothing changed. Held only
    /// in memory: after a restart the first upsert per entity may write one
    /// redundant version (RSA ciphertexts are non-deterministic, so equality
    /// cannot be recovered from disk without the private key).
    fingerprints: HashMap<String, String>,
}

impl TypeRegistry {
    pub fn open(
        dir: &Path,
        schema: TypeSchema,
        max_segment_bytes: u64,
        cache_plaintexts: bool,
    ) -> Result<Self> {
        for f in &schema.fields {
            if f.indexed && f.protection == FieldProtection::Rsa {
                return Err(Error::Schema(format!(
                    "field '{}' of type '{}': RSA-encrypted fields cannot be indexed",
                    f.name, schema.type_name
                )));
            }
            match f.search {
                FieldIndex::None => {}
                FieldIndex::Prefix(0) | FieldIndex::Ngram(0) => {
                    return Err(Error::Schema(format!(
                        "field '{}' of type '{}': FieldIndex size must be >= 1",
                        f.name, schema.type_name
                    )));
                }
                _ if f.kind != ValueKind::Text => {
                    return Err(Error::Schema(format!(
                        "field '{}' of type '{}': FieldIndex requires a Text field",
                        f.name, schema.type_name
                    )));
                }
                _ => {}
            }
        }
        let mut table = Table::open(dir, max_segment_bytes)?;
        let mut idx = RegistryIndex::new(schema, cache_plaintexts);
        // rebuild in-memory state from the version log
        let records: Vec<RegistryRecord> = table.scan()?.collect::<Result<Vec<_>>>()?;
        for rec in records {
            idx.absorb(rec);
        }
        Ok(Self {
            table,
            idx,
            fingerprints: HashMap::new(),
        })
    }

    pub fn schema(&self) -> &TypeSchema {
        &self.idx.schema
    }

    /// Register or update an entity. Returns the uid of its *current* version:
    /// a fresh one if the field values changed (or the entity is new /
    /// resurrected), the existing one if nothing changed.
    pub fn upsert(&mut self, input: &EntityInput, keys: &KeyRing) -> Result<Uid> {
        self.validate(input)?;
        let fp = fingerprint(input);
        if let Some(prev_fp) = self.fingerprints.get(&input.entity_id) {
            if *prev_fp == fp {
                if let Some(uid) = self.idx.latest_uid(&input.entity_id) {
                    if !self.idx.version(&uid).unwrap().deleted {
                        return Ok(uid);
                    }
                }
            }
        }
        let uid = Uid::generate();
        let mut fields = BTreeMap::new();
        let mut token_map = BTreeMap::new();
        for def in &self.idx.schema.fields {
            if let Some(v) = input.fields.get(&def.name) {
                fields.insert(def.name.clone(), keys.protect(v, def.protection)?);
                // blind-index tokens must be derived now, while the plaintext
                // exists — for protected fields it is not on disk to re-derive
                if def.search != FieldIndex::None {
                    if let Value::Text(s) = v {
                        let mut key_version = crate::crypto::KEYLESS;
                        let mut digests = Vec::new();
                        for t in tokens::value_tokens(s, def.search) {
                            let (v, d) = keys.index_token_digest(&def.name, def.protection, &t)?;
                            key_version = v; // same active key for every token
                            digests.push(d);
                        }
                        token_map.insert(
                            def.name.clone(),
                            FieldTokens {
                                key_version,
                                digests,
                            },
                        );
                    }
                }
                // hold the plaintext in memory so protected fields written by
                // this process stay LIKE-searchable (never persisted; opt-in)
                if self.idx.cache_plaintexts && def.protection != FieldProtection::None {
                    self.idx
                        .held
                        .insert((uid, def.name.clone()), v.canonical_bytes());
                }
            }
        }
        let version = self
            .idx
            .versions
            .get(&input.entity_id)
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        let rec = RegistryRecord {
            uid,
            entity_id: input.entity_id.clone(),
            entity_type: self.idx.schema.type_name.clone(),
            version,
            recorded_at: crate::time::now_micros(),
            deleted: false,
            fields,
            tokens: token_map,
        };
        self.table.append(&rec, rec.recorded_at)?;
        self.table.flush()?;
        self.idx.absorb(rec);
        self.fingerprints.insert(input.entity_id.clone(), fp);
        Ok(uid)
    }

    /// Mark an entity deleted. History (all prior versions) remains searchable
    /// and logs that referenced it still render the as-recorded values.
    pub fn delete(&mut self, entity_id: &str) -> Result<Uid> {
        let latest = self
            .idx
            .latest(entity_id)
            .ok_or_else(|| Error::NotFound(format!("entity '{entity_id}'")))?
            .clone();
        let rec = RegistryRecord {
            uid: Uid::generate(),
            entity_id: latest.entity_id.clone(),
            entity_type: latest.entity_type.clone(),
            version: latest.version + 1,
            recorded_at: crate::time::now_micros(),
            deleted: true,
            fields: latest.fields.clone(),
            tokens: latest.tokens.clone(),
        };
        self.table.append(&rec, rec.recorded_at)?;
        self.table.flush()?;
        let uid = rec.uid;
        self.idx.absorb(rec);
        self.fingerprints.remove(entity_id);
        Ok(uid)
    }

    fn validate(&self, input: &EntityInput) -> Result<()> {
        for def in &self.idx.schema.fields {
            match input.fields.get(&def.name) {
                Some(v) if v.kind() != def.kind => {
                    return Err(Error::Schema(format!(
                        "field '{}' expects {:?}, got {:?}",
                        def.name,
                        def.kind,
                        v.kind()
                    )));
                }
                None if def.required => {
                    return Err(Error::Schema(format!(
                        "missing required field '{}'",
                        def.name
                    )));
                }
                _ => {}
            }
        }
        for name in input.fields.keys() {
            if self.idx.schema.field(name).is_none() {
                return Err(Error::Schema(format!(
                    "unknown field '{}' for type '{}'",
                    name, self.idx.schema.type_name
                )));
            }
        }
        Ok(())
    }

    /// See [`RegistryIndex::search`].
    pub fn search(
        &mut self,
        field: &str,
        probe: &Value,
        include_past: bool,
        mode: MatchMode,
        keys: &KeyRing,
    ) -> Result<Vec<String>> {
        self.idx.search(field, probe, include_past, mode, keys)
    }

    pub fn latest_uid(&self, entity_id: &str) -> Option<Uid> {
        self.idx.latest_uid(entity_id)
    }

    pub fn latest(&self, entity_id: &str) -> Option<&RegistryRecord> {
        self.idx.latest(entity_id)
    }

    pub fn version(&self, uid: &Uid) -> Option<&RegistryRecord> {
        self.idx.version(uid)
    }

    pub fn all_version_uids(&self, entity_id: &str) -> &[Uid] {
        self.idx.all_version_uids(entity_id)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.table.sync()
    }

    /// Verify the tamper-evidence chain of this registry's version log.
    pub fn verify(&mut self) -> Result<()> {
        self.table.verify()
    }

    /// Whether `target` is a chain value (or segment seed) of this registry's
    /// version log — used to verify that the chain head signed by the latest
    /// re-key event still exists in the chain.
    pub(crate) fn contains_chain_value(
        &mut self,
        target: &crate::storage::ChainHash,
    ) -> Result<bool> {
        self.table.contains_chain_value(target)
    }
}

/// Search key for an on-disk value: plain values use canonical bytes, hashed
/// values use the hex digest. RSA values are unsearchable -> no key.
fn index_key(stored: &StoredValue) -> Option<Vec<u8>> {
    match stored {
        StoredValue::Plain(v) => Some(v.canonical_bytes()),
        StoredValue::Sha256(hex) => Some(hex.as_bytes().to_vec()),
        StoredValue::Hmac { digest, .. } => Some(digest.as_bytes().to_vec()),
        StoredValue::Rsa { .. } => None,
    }
}

/// Probe value as text, for normalized-token searches.
fn probe_text(v: &Value) -> String {
    String::from_utf8_lossy(&v.canonical_bytes()).into_owned()
}

fn contains(hay: &[u8], pat: &[u8]) -> bool {
    pat.is_empty() || hay.windows(pat.len()).any(|w| w == pat)
}

fn fingerprint(input: &EntityInput) -> String {
    let mut buf = Vec::new();
    for (k, v) in &input.fields {
        buf.extend_from_slice(k.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&v.canonical_bytes());
        buf.push(0);
    }
    sha256_hex(&buf)
}
