use crate::crypto::KeyRing;
use crate::error::{Error, Result};
use crate::id::Uid;
use crate::model::{AuditLog, Content, TargetRelation, Value};
use crate::query::{LogQuery, LogView, TargetFilter, TargetSnapshot};
use crate::registry::{EntityInput, RegistryIndex, RegistryRecord, TypeRegistry};
use crate::retention::RetentionPolicy;
use crate::schema::{CustomColumnDef, TypeSchema};
use crate::storage::{SegmentSlice, Table, TableScan};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

/// Durability/throughput trade-off for log appends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPolicy {
    /// fsync after every append. Safest, slowest.
    Always,
    /// fsync after every N appends; otherwise only flush to the OS cache.
    EveryN(u32),
    /// Never fsync explicitly; rely on the OS to write back. Fastest.
    OsManaged,
}

#[derive(Clone)]
pub struct StoreConfig {
    pub root: PathBuf,
    pub max_segment_bytes: u64,
    pub sync_policy: SyncPolicy,
    pub retention: RetentionPolicy,
    pub keys: KeyRing,
    /// Opt-in for LIKE ([`crate::MatchMode::Contains`]) search on *protected*
    /// fields: plaintexts of protected values written by this process are
    /// held in memory (never persisted), and RSA values are decrypted and
    /// cached per immutable version on first Contains search. Off by
    /// default — keeping plaintexts of protected fields in memory is a
    /// deliberate trade-off the operator must choose; when off, Contains on
    /// protected fields is rejected (plain fields are always LIKE-searchable).
    pub plaintext_cache: bool,
}

impl StoreConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_segment_bytes: 64 * 1024 * 1024,
            sync_policy: SyncPolicy::EveryN(64),
            retention: RetentionPolicy::KeepForever,
            keys: KeyRing::new(),
            plaintext_cache: false,
        }
    }

    /// Enable the in-memory plaintext cache — see
    /// [`plaintext_cache`](Self::plaintext_cache).
    pub fn plaintext_cache(mut self, enabled: bool) -> Self {
        self.plaintext_cache = enabled;
        self
    }

    pub fn retention(mut self, r: RetentionPolicy) -> Self {
        self.retention = r;
        self
    }

    pub fn sync_policy(mut self, p: SyncPolicy) -> Self {
        self.sync_policy = p;
        self
    }

    pub fn keys(mut self, k: KeyRing) -> Self {
        self.keys = k;
        self
    }

    pub fn max_segment_bytes(mut self, n: u64) -> Self {
        self.max_segment_bytes = n;
        self
    }
}

/// Persisted meta events: schema and custom-column definitions are themselves
/// stored in an append-only table and replayed on open.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MetaEvent {
    TypeDefined(TypeSchema),
    CustomColumnDefined(CustomColumnDef),
}

/// The embedded audit store. Owns every table under one root directory:
///
/// ```text
/// root/
///   meta/         type schemas + custom column registry (replayed on open)
///   logs/         AuditLog rows
///   relations/    log -> target-entity-version relations
///   registry/<t>/ one versioned registry table per entity/actor type
/// ```
pub struct AuditStore {
    cfg: StoreConfig,
    meta: Table<MetaEvent>,
    logs: Table<AuditLog>,
    relations: Table<TargetRelation>,
    registries: HashMap<String, TypeRegistry>,
    custom_columns: HashMap<String, CustomColumnDef>,
    appends_since_sync: u32,
    /// Advisory OS lock on `root/LOCK`, held for the store's lifetime. The
    /// store is single-process by design; without this, a second process
    /// opening the same root would silently corrupt in-memory indexes and
    /// interleave segment writes. Released automatically on drop/crash.
    _lock: std::fs::File,
}

impl AuditStore {
    pub fn open(cfg: StoreConfig) -> Result<Self> {
        std::fs::create_dir_all(&cfg.root)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(cfg.root.join("LOCK"))?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => Error::Locked(cfg.root.display().to_string()),
            std::fs::TryLockError::Error(e) => Error::Io(e),
        })?;
        let mut meta: Table<MetaEvent> =
            Table::open(&cfg.root.join("meta"), cfg.max_segment_bytes)?;
        let logs = Table::open(&cfg.root.join("logs"), cfg.max_segment_bytes)?;
        let relations = Table::open(&cfg.root.join("relations"), cfg.max_segment_bytes)?;

        let mut registries = HashMap::new();
        let mut custom_columns = HashMap::new();
        let events: Vec<MetaEvent> = meta.scan()?.collect::<Result<Vec<_>>>()?;
        for ev in events {
            match ev {
                MetaEvent::TypeDefined(schema) => {
                    // last definition wins (allows additive schema evolution)
                    let dir = cfg.root.join("registry").join(&schema.type_name);
                    let reg = TypeRegistry::open(
                        &dir,
                        schema.clone(),
                        cfg.max_segment_bytes,
                        cfg.plaintext_cache,
                    )?;
                    registries.insert(schema.type_name.clone(), reg);
                }
                MetaEvent::CustomColumnDefined(def) => {
                    custom_columns.insert(def.name.clone(), def);
                }
            }
        }
        Ok(Self {
            cfg,
            meta,
            logs,
            relations,
            registries,
            custom_columns,
            appends_since_sync: 0,
            _lock: lock,
        })
    }

    // ---- schema management -------------------------------------------------

    /// Create (or redefine) the registry table for an entity/actor type.
    /// Must be called before entities of that type are registered — this is
    /// the "create the registry table first" step of the write protocol.
    ///
    /// Redefinition is additive only: new fields may be added, but existing
    /// fields cannot be removed or change kind/protection. A protection
    /// change would split the search index keys (old values silently stop
    /// matching probes), breaking the "past values stay searchable" promise.
    pub fn define_type(&mut self, schema: TypeSchema) -> Result<()> {
        if let Some(existing) = self.registries.get(&schema.type_name) {
            for old in &existing.schema().fields {
                match schema.field(&old.name) {
                    None => {
                        return Err(Error::Schema(format!(
                            "type '{}': field '{}' cannot be removed — recorded data still \
                             references it",
                            schema.type_name, old.name
                        )));
                    }
                    Some(new) if new.kind != old.kind || new.protection != old.protection => {
                        return Err(Error::Schema(format!(
                            "type '{}': field '{}' cannot change kind/protection — existing \
                             values would become unsearchable or unreadable",
                            schema.type_name, old.name
                        )));
                    }
                    _ => {}
                }
            }
        }
        let dir = self.cfg.root.join("registry").join(&schema.type_name);
        let reg = TypeRegistry::open(
            &dir,
            schema.clone(),
            self.cfg.max_segment_bytes,
            self.cfg.plaintext_cache,
        )?;
        self.meta.append(
            &MetaEvent::TypeDefined(schema.clone()),
            crate::time::now_micros(),
        )?;
        self.meta.sync()?;
        self.registries.insert(schema.type_name.clone(), reg);
        Ok(())
    }

    pub fn has_type(&self, type_name: &str) -> bool {
        self.registries.contains_key(type_name)
    }

    /// Register an extra audit-log column (text / number / json). For
    /// `required` columns, the requirement only applies to events that occur
    /// from now on — see [`CustomColumnDef::required_since`].
    pub fn define_custom_column(&mut self, mut def: CustomColumnDef) -> Result<()> {
        if def.required && def.required_since.is_none() {
            def.required_since = Some(crate::time::now_micros());
        }
        self.meta.append(
            &MetaEvent::CustomColumnDefined(def.clone()),
            crate::time::now_micros(),
        )?;
        self.meta.sync()?;
        self.custom_columns.insert(def.name.clone(), def);
        Ok(())
    }

    pub fn custom_columns(&self) -> impl Iterator<Item = &CustomColumnDef> {
        self.custom_columns.values()
    }

    // ---- registry operations -----------------------------------------------

    fn registry(&mut self, type_name: &str) -> Result<&mut TypeRegistry> {
        self.registries.get_mut(type_name).ok_or_else(|| {
            Error::Schema(format!(
                "type '{type_name}' has no registry table — call define_type() first"
            ))
        })
    }

    /// Register/update an entity and get the uid of its current version.
    pub fn register_entity(&mut self, type_name: &str, input: &EntityInput) -> Result<Uid> {
        let keys = self.cfg.keys.clone();
        self.registry(type_name)?.upsert(input, &keys)
    }

    /// Update is the same operation as register: changed fields produce a new
    /// version, old versions stay queryable (old-name search keeps working).
    pub fn update_entity(&mut self, type_name: &str, input: &EntityInput) -> Result<Uid> {
        self.register_entity(type_name, input)
    }

    pub fn delete_entity(&mut self, type_name: &str, entity_id: &str) -> Result<Uid> {
        self.registry(type_name)?.delete(entity_id)
    }

    pub fn entity_latest(&self, type_name: &str, entity_id: &str) -> Option<&RegistryRecord> {
        self.registries.get(type_name)?.latest(entity_id)
    }

    // ---- writing logs --------------------------------------------------------

    /// Append one audit log following the full write protocol:
    /// 1. the actor is upserted into its type registry,
    /// 2. every target is upserted into its type registry,
    /// 3. the log row is appended with the actor's version uid,
    /// 4. one relation row per target binds the log to the exact entity versions.
    ///
    /// Registry tables for every referenced type must already exist.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        actor_type: &str,
        actor: &EntityInput,
        method: &str,
        url: &str,
        content: Content,
        targets: &[(String, EntityInput)],
        custom: BTreeMap<String, Value>,
    ) -> Result<Uid> {
        self.append_at(
            crate::time::now_micros(),
            actor_type,
            actor,
            method,
            url,
            content,
            targets,
            custom,
        )
    }

    /// [`append`](Self::append) with an explicit event time — for events that
    /// occurred earlier than they are persisted (async pipelines, DLQ
    /// redrive). Validation of required custom columns uses this time, so a
    /// column made required *after* the event happened does not reject it.
    #[allow(clippy::too_many_arguments)]
    pub fn append_at(
        &mut self,
        occurred_at: u64,
        actor_type: &str,
        actor: &EntityInput,
        method: &str,
        url: &str,
        content: Content,
        targets: &[(String, EntityInput)],
        custom: BTreeMap<String, Value>,
    ) -> Result<Uid> {
        self.validate_custom(&custom, occurred_at)?;
        let actor_uid = self.register_entity(actor_type, actor)?;
        let mut target_refs = Vec::with_capacity(targets.len());
        for (t_type, t_input) in targets {
            let uid = self.register_entity(t_type, t_input)?;
            target_refs.push((t_type.clone(), uid));
        }
        self.append_resolved_at(
            occurred_at,
            actor_type,
            actor_uid,
            method,
            url,
            content,
            &target_refs,
            custom,
        )
    }

    /// Lower-level append for callers that already hold registry version uids.
    #[allow(clippy::too_many_arguments)]
    pub fn append_resolved(
        &mut self,
        actor_type: &str,
        actor_uid: Uid,
        method: &str,
        url: &str,
        content: Content,
        targets: &[(String, Uid)],
        custom: BTreeMap<String, Value>,
    ) -> Result<Uid> {
        self.append_resolved_at(
            crate::time::now_micros(),
            actor_type,
            actor_uid,
            method,
            url,
            content,
            targets,
            custom,
        )
    }

    /// See [`append_at`](Self::append_at).
    #[allow(clippy::too_many_arguments)]
    pub fn append_resolved_at(
        &mut self,
        occurred_at: u64,
        actor_type: &str,
        actor_uid: Uid,
        method: &str,
        url: &str,
        content: Content,
        targets: &[(String, Uid)],
        custom: BTreeMap<String, Value>,
    ) -> Result<Uid> {
        self.validate_custom(&custom, occurred_at)?;
        let log = AuditLog {
            log_id: Uid::generate(),
            timestamp: occurred_at,
            actor: actor_uid,
            actor_type: actor_type.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            content,
            custom,
        };
        self.logs.append(&log, log.timestamp)?;
        for (entity_type, uid) in targets {
            let rel = TargetRelation {
                log_id: log.log_id,
                entity_registry_uid: *uid,
                entity_type: entity_type.clone(),
            };
            self.relations.append(&rel, log.timestamp)?;
        }
        self.apply_sync_policy()?;
        Ok(log.log_id)
    }

    fn validate_custom(&self, custom: &BTreeMap<String, Value>, occurred_at: u64) -> Result<()> {
        for (name, value) in custom {
            let def = self.custom_columns.get(name).ok_or_else(|| {
                Error::Schema(format!(
                    "custom column '{name}' is not registered — call define_custom_column()"
                ))
            })?;
            if value.kind() != def.kind {
                return Err(Error::Schema(format!(
                    "custom column '{name}' expects {:?}, got {:?}",
                    def.kind,
                    value.kind()
                )));
            }
        }
        for def in self.custom_columns.values() {
            let in_force = def.required_since.is_none_or(|since| occurred_at >= since);
            if def.required && in_force && !custom.contains_key(&def.name) {
                return Err(Error::Schema(format!(
                    "missing required custom column '{}'",
                    def.name
                )));
            }
        }
        Ok(())
    }

    fn apply_sync_policy(&mut self) -> Result<()> {
        match self.cfg.sync_policy {
            SyncPolicy::Always => self.sync_all()?,
            SyncPolicy::EveryN(n) => {
                self.appends_since_sync += 1;
                if self.appends_since_sync >= n {
                    self.sync_all()?;
                } else {
                    self.logs.flush()?;
                    self.relations.flush()?;
                }
            }
            SyncPolicy::OsManaged => {
                self.logs.flush()?;
                self.relations.flush()?;
            }
        }
        Ok(())
    }

    /// fsync in dependency order: a log row must never be durable while the
    /// registry version it references is not — a crash would otherwise leave
    /// logs pointing at registry records that evaporated.
    fn sync_all(&mut self) -> Result<()> {
        for reg in self.registries.values_mut() {
            reg.sync()?;
        }
        self.logs.sync()?;
        self.relations.sync()?;
        self.appends_since_sync = 0;
        Ok(())
    }

    /// Force everything to durable storage.
    pub fn sync(&mut self) -> Result<()> {
        self.sync_all()?;
        self.meta.sync()?;
        Ok(())
    }

    /// Verify the tamper-evidence hash chains of every table (logs, relations,
    /// meta, all registries). Returns the first chain break found — a record
    /// that was modified in place, or a segment that was removed/replaced.
    pub fn verify_integrity(&mut self) -> Result<()> {
        self.logs.verify()?;
        self.relations.verify()?;
        self.meta.verify()?;
        for reg in self.registries.values_mut() {
            reg.verify()?;
        }
        Ok(())
    }

    // ---- retention -----------------------------------------------------------

    /// Enforce the configured retention window now. Returns segments dropped.
    pub fn apply_retention(&mut self) -> Result<usize> {
        let Some(cutoff) = self.cfg.retention.cutoff_micros(crate::time::now_micros()) else {
            return Ok(0);
        };
        let mut dropped = self.logs.purge_older_than(cutoff)?;
        dropped += self.relations.purge_older_than(cutoff)?;
        Ok(dropped)
    }

    // ---- registry browsing -----------------------------------------------------

    /// Schemas of every defined entity/actor type, sorted by type name.
    pub fn type_schemas(&self) -> Vec<TypeSchema> {
        let mut out: Vec<TypeSchema> = self
            .registries
            .values()
            .map(|r| r.schema().clone())
            .collect();
        out.sort_by(|a, b| a.type_name.cmp(&b.type_name));
        out
    }

    /// Latest version of every entity of a type, sorted by entity_id.
    pub fn list_entities(
        &self,
        type_name: &str,
        include_deleted: bool,
    ) -> Result<Vec<TargetSnapshot>> {
        let reg = self
            .registries
            .get(type_name)
            .ok_or_else(|| Error::Schema(format!("type '{type_name}' has no registry table")))?;
        let mut ids: Vec<&String> = reg.idx.entity_ids().collect();
        ids.sort();
        Ok(ids
            .into_iter()
            .filter_map(|id| reg.latest(id))
            .filter(|rec| include_deleted || !rec.deleted)
            .map(snapshot_of)
            .collect())
    }

    /// Full version history of one entity, oldest first (a delete shows up as
    /// a final version with `deleted: true`).
    pub fn entity_history(&self, type_name: &str, entity_id: &str) -> Result<Vec<TargetSnapshot>> {
        let reg = self
            .registries
            .get(type_name)
            .ok_or_else(|| Error::Schema(format!("type '{type_name}' has no registry table")))?;
        let uids = reg.all_version_uids(entity_id);
        if uids.is_empty() {
            return Err(Error::NotFound(format!(
                "entity '{entity_id}' of type '{type_name}'"
            )));
        }
        Ok(uids
            .iter()
            .map(|uid| match reg.version(uid) {
                Some(rec) => snapshot_of(rec),
                None => missing_snapshot(type_name, uid),
            })
            .collect())
    }

    // ---- queries ---------------------------------------------------------------

    /// A point-in-time, read-only view of the store. Building it is cheap
    /// (registry indexes are cloned, log/relation tables contribute only
    /// path+length bounds); the actual scan then runs on the snapshot without
    /// touching the store, so a slow full-scan query never blocks appends.
    pub fn snapshot(&mut self) -> Result<ReadSnapshot> {
        Ok(ReadSnapshot {
            keys: self.cfg.keys.clone(),
            registries: self
                .registries
                .iter()
                .map(|(k, v)| (k.clone(), v.idx.clone()))
                .collect(),
            logs: self.logs.slices()?,
            relations: self.relations.slices()?,
        })
    }

    /// Run a query. Targets and actor are resolved to the registry versions
    /// referenced at write time, so renamed entities show their historical
    /// values. Convenience for [`snapshot`](Self::snapshot)`()?.query(q)`.
    pub fn query(&mut self, q: &LogQuery) -> Result<Vec<LogView>> {
        self.snapshot()?.query(q)
    }

    /// Decrypt an RSA-protected stored value (requires the private key).
    pub fn decrypt(&self, v: &crate::model::StoredValue) -> Result<Vec<u8>> {
        self.cfg.keys.decrypt(v)
    }
}

fn snapshot_of(rec: &crate::registry::RegistryRecord) -> TargetSnapshot {
    TargetSnapshot {
        entity_registry_uid: rec.uid,
        entity_type: rec.entity_type.clone(),
        entity_id: rec.entity_id.clone(),
        version: rec.version,
        fields: rec.fields.clone(),
        deleted: rec.deleted,
        missing: false,
    }
}

fn missing_snapshot(entity_type: &str, uid: &Uid) -> TargetSnapshot {
    TargetSnapshot {
        entity_registry_uid: *uid,
        entity_type: entity_type.to_string(),
        entity_id: String::new(),
        version: 0,
        fields: BTreeMap::new(),
        deleted: false,
        missing: true,
    }
}

/// A point-in-time, read-only view of an [`AuditStore`] (see
/// [`AuditStore::snapshot`]). `Send`, so it can be handed to another thread:
/// the async pipeline runs query scans on the *caller's* thread against a
/// snapshot, which keeps the writer thread free to persist events — a slow
/// full-scan query can no longer push `emit` into `QueueFull` territory.
/// Rows appended after the snapshot was taken are not visible.
pub struct ReadSnapshot {
    keys: KeyRing,
    registries: HashMap<String, RegistryIndex>,
    logs: Vec<SegmentSlice>,
    relations: Vec<SegmentSlice>,
}

impl ReadSnapshot {
    /// Run a query against this snapshot. `&mut self` because Contains
    /// searches lazily decrypt-and-cache RSA values.
    pub fn query(&mut self, q: &LogQuery) -> Result<Vec<LogView>> {
        // 1. resolve entity filters to allowed log_id sets via the relation
        //    table; multiple target filters intersect (AND)
        let mut allowed_by_target: Option<HashSet<Uid>> = None;
        for f in &q.targets {
            let ids = self.log_ids_for_filter(f)?;
            allowed_by_target = Some(match allowed_by_target {
                Some(prev) => prev.intersection(&ids).copied().collect(),
                None => ids,
            });
        }
        let allowed_actor_uids: Option<HashSet<Uid>> = match &q.actor {
            Some(f) => Some(self.version_uids_for_filter(f)?),
            None => None,
        };

        // 2. group relations per log so each hit can render its targets
        let mut rels_by_log: HashMap<Uid, Vec<TargetRelation>> = HashMap::new();
        for rel in TableScan::<TargetRelation>::over(self.relations.clone()) {
            let rel = rel?;
            rels_by_log.entry(rel.log_id).or_default().push(rel);
        }

        // 3. stream the log table and apply all conditions
        let mut hits = Vec::new();
        for row in TableScan::<AuditLog>::over(self.logs.clone()) {
            let log = row?;
            if let Some(from) = q.from_micros {
                if log.timestamp < from {
                    continue;
                }
            }
            if let Some(to) = q.to_micros {
                if log.timestamp > to {
                    continue;
                }
            }
            if let Some(m) = &q.method {
                if !log.method.eq_ignore_ascii_case(m) {
                    continue;
                }
            }
            if let Some(p) = &q.url_prefix {
                if !log.url.starts_with(p.as_str()) {
                    continue;
                }
            }
            if let Some(allowed) = &allowed_by_target {
                if !allowed.contains(&log.log_id) {
                    continue;
                }
            }
            if let Some(uids) = &allowed_actor_uids {
                if !uids.contains(&log.actor) {
                    continue;
                }
            }
            if !q.custom.iter().all(|(k, v)| log.custom.get(k) == Some(v)) {
                continue;
            }
            hits.push(self.render(log, &rels_by_log));
            if let Some(limit) = q.limit {
                if hits.len() >= limit {
                    break;
                }
            }
        }
        Ok(hits)
    }

    /// All log_ids whose relations point at an entity matching the filter.
    /// Matching is by *entity*, not version: searching the current name also
    /// finds logs recorded under an older name, and vice versa.
    fn log_ids_for_filter(&mut self, f: &TargetFilter) -> Result<HashSet<Uid>> {
        let version_uids = self.version_uids_for_filter(f)?;
        let mut out = HashSet::new();
        for rel in TableScan::<TargetRelation>::over(self.relations.clone()) {
            let rel = rel?;
            if version_uids.contains(&rel.entity_registry_uid) {
                out.insert(rel.log_id);
            }
        }
        Ok(out)
    }

    /// Every version uid of every entity matching the filter.
    fn version_uids_for_filter(&mut self, f: &TargetFilter) -> Result<HashSet<Uid>> {
        let reg = self.registries.get_mut(&f.entity_type).ok_or_else(|| {
            Error::Schema(format!("type '{}' has no registry table", f.entity_type))
        })?;
        let entity_ids = reg.search(&f.field, &f.value, f.include_past, f.mode, &self.keys)?;
        let mut uids = HashSet::new();
        for id in entity_ids {
            uids.extend(reg.all_version_uids(&id).iter().copied());
        }
        Ok(uids)
    }

    fn render(&self, log: AuditLog, rels_by_log: &HashMap<Uid, Vec<TargetRelation>>) -> LogView {
        let actor = self.snapshot(&log.actor_type, &log.actor);
        let mut targets = Vec::new();
        if let Some(rels) = rels_by_log.get(&log.log_id) {
            for rel in rels {
                targets.push(self.snapshot(&rel.entity_type, &rel.entity_registry_uid));
            }
        }
        LogView {
            log_id: log.log_id,
            timestamp_micros: log.timestamp,
            timestamp: crate::time::format_rfc3339(log.timestamp),
            actor,
            method: log.method,
            url: log.url,
            content: log.content,
            targets,
            custom: log.custom,
        }
    }

    /// Resolve one registry version. An unresolvable reference renders as a
    /// `missing` placeholder instead of an error: one broken/lost registry
    /// record must not make every query touching that log fail.
    fn snapshot(&self, entity_type: &str, uid: &Uid) -> TargetSnapshot {
        match self
            .registries
            .get(entity_type)
            .and_then(|r| r.version(uid))
        {
            Some(rec) => snapshot_of(rec),
            None => missing_snapshot(entity_type, uid),
        }
    }
}
