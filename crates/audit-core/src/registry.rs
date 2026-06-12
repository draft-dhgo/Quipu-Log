use crate::crypto::{sha256_hex, KeyRing};
use crate::error::{Error, Result};
use crate::id::Uid;
use crate::model::{StoredValue, Value};
use crate::query::MatchMode;
use crate::schema::{FieldProtection, TypeSchema};
use crate::storage::Table;
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
                let key = match def.protection {
                    FieldProtection::None => probe.canonical_bytes(),
                    FieldProtection::Sha256 => sha256_hex(&probe.canonical_bytes()).into_bytes(),
                    FieldProtection::Hmac => keys.hmac_hex(&probe.canonical_bytes())?.into_bytes(),
                    FieldProtection::Rsa => unreachable!("rsa fields are rejected at open()"),
                };
                let Some(ids) = self.index.get(field).and_then(|m| m.get(&key)) else {
                    return Ok(Vec::new());
                };
                let mut out: Vec<String> = if include_past {
                    ids.iter().cloned().collect()
                } else {
                    ids.iter()
                        .filter(|id| {
                            self.latest(id).is_some_and(|rec| {
                                !rec.deleted
                                    && rec.fields.get(field).and_then(index_key).as_deref()
                                        == Some(&key[..])
                            })
                        })
                        .cloned()
                        .collect()
                };
                out.sort();
                Ok(out)
            }
            MatchMode::Contains => {
                if def.protection != FieldProtection::None && !self.cache_plaintexts {
                    return Err(Error::Schema(format!(
                        "field '{field}' is protected and the plaintext cache is disabled — \
                         enable StoreConfig::plaintext_cache to LIKE-search protected fields, \
                         or use exact match"
                    )));
                }
                // full scan over the in-memory registry (no index needed)
                let pat = probe.canonical_bytes();
                let uids: Vec<Uid> = if include_past {
                    self.by_uid.keys().copied().collect()
                } else {
                    self.versions
                        .values()
                        .filter_map(|v| v.last().copied())
                        .filter(|u| !self.by_uid[u].deleted)
                        .collect()
                };
                let mut hits = HashSet::new();
                for uid in uids {
                    if let Some(hay) = self.plaintext_of(uid, field, keys)? {
                        if contains(&hay, &pat) {
                            hits.insert(self.by_uid[&uid].entity_id.clone());
                        }
                    }
                }
                let mut out: Vec<String> = hits.into_iter().collect();
                out.sort();
                Ok(out)
            }
        }
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
            StoredValue::Sha256(_) | StoredValue::Hmac(_) => {
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
        for def in &self.idx.schema.fields {
            if let Some(v) = input.fields.get(&def.name) {
                fields.insert(def.name.clone(), keys.protect(v, def.protection)?);
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
}

/// Search key for an on-disk value: plain values use canonical bytes, hashed
/// values use the hex digest. RSA values are unsearchable -> no key.
fn index_key(stored: &StoredValue) -> Option<Vec<u8>> {
    match stored {
        StoredValue::Plain(v) => Some(v.canonical_bytes()),
        StoredValue::Sha256(hex) | StoredValue::Hmac(hex) => Some(hex.as_bytes().to_vec()),
        StoredValue::Rsa { .. } => None,
    }
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
