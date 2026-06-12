use crate::event::AuditEvent;
use crate::health::{disk_usage, DiskThresholds, HealthSnapshot, HealthState};
use crate::metrics::{MetricsSnapshot, PipelineMetrics};
use crate::permissions::{Action, PermissionPolicy, Role};
use quipu_core::storage::{SegmentSlice, Table, TableScan};
use quipu_core::{
    AuditLog, AuditStore, CustomColumnDef, LogQuery, LogView, ReadSnapshot, TargetSnapshot,
    TypeSchema, Uid,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

/// Why an interaction with the pipeline failed.
#[derive(Debug)]
pub enum MiddlewareError {
    /// The bounded event queue is full; the event is handed back so the caller
    /// can decide (drop, retry later, write to its own fallback).
    QueueFull(Box<AuditEvent>),
    PermissionDenied {
        role: Role,
        action: Action,
    },
    /// The worker thread has stopped.
    WorkerGone,
    /// The disk-full latch is set and the pipeline is configured to reject
    /// emits fast instead of queueing events that cannot be persisted (see
    /// [`PipelineConfig::reject_emit_when_disk_full`]). The event is handed
    /// back so the caller can route it to its own fallback.
    DiskFull(Box<AuditEvent>),
    Core(quipu_core::Error),
}

impl std::fmt::Display for MiddlewareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiddlewareError::QueueFull(_) => write!(f, "audit event queue is full"),
            MiddlewareError::PermissionDenied { role, action } => {
                write!(f, "role '{}' is not allowed to {:?}", role.0, action)
            }
            MiddlewareError::WorkerGone => write!(f, "audit worker thread has stopped"),
            MiddlewareError::DiskFull(_) => {
                write!(f, "audit store disk is full; event rejected")
            }
            MiddlewareError::Core(e) => write!(f, "audit store error: {e}"),
        }
    }
}

impl std::error::Error for MiddlewareError {}

/// An event parked after exhausting retries. Redrive replays these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntry {
    pub event: AuditEvent,
    pub error: String,
    pub failed_at: u64,
}

/// Outcome of one tamper-evidence verification pass over the whole store
/// (see [`AuditHandle::verify_integrity`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    /// `true` when every hash chain checked out.
    pub ok: bool,
    /// Segment files across all tables (logs, relations, meta, registries).
    pub segments_checked: usize,
    /// Rows readable in the audit-log table at verification time.
    pub log_records: usize,
    /// Chain breaks or read errors. The core verification stops at the first
    /// break, so today this holds at most one entry.
    pub problems: Vec<String>,
}

/// Called when an event could not be persisted and went to the DLQ (or the
/// DLQ itself failed). Lets the host page someone, mirror to stderr, etc.
pub type FallbackFn = Arc<dyn Fn(&AuditEvent, &str) + Send + Sync>;

#[derive(Clone)]
pub struct PipelineConfig {
    /// Bounded queue between the host app and the writer thread.
    pub queue_capacity: usize,
    /// Write attempts per event before it is parked in the DLQ.
    pub max_retries: u32,
    pub retry_backoff: Duration,
    /// How often the idle worker enforces retention and fsyncs.
    pub housekeeping_interval: Duration,
    /// Where DLQ segments live (defaults to `<store root>/dlq`).
    pub dlq_dir: Option<PathBuf>,
    /// When free space under the store root drops below either bound, the
    /// pipeline logs a warning, notifies the fallback hook once (on the
    /// transition) and reports `low_disk` through [`AuditHandle::health`].
    pub disk_thresholds: DiskThresholds,
    /// When `true`, `emit` fails fast with [`MiddlewareError::DiskFull`]
    /// (handing the event back) while the disk-full latch is set, instead of
    /// queueing events that are bound for the fallback hook anyway. Off by
    /// default: queued events would still be persisted if space frees up
    /// before they reach the writer.
    pub reject_emit_when_disk_full: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            max_retries: 3,
            retry_backoff: Duration::from_millis(20),
            housekeeping_interval: Duration::from_secs(30),
            dlq_dir: None,
            disk_thresholds: DiskThresholds::default(),
            reject_emit_when_disk_full: false,
        }
    }
}

enum Command {
    Emit(Box<AuditEvent>),
    /// Flush everything and stop the worker loop.
    Shutdown(SyncSender<()>),
    Snapshot(SyncSender<Result<Box<ReadSnapshot>, MiddlewareError>>),
    EntityTypes(SyncSender<Result<Vec<TypeSchema>, MiddlewareError>>),
    ListEntities {
        type_name: String,
        include_deleted: bool,
        reply: SyncSender<Result<Vec<TargetSnapshot>, MiddlewareError>>,
    },
    EntityHistory {
        type_name: String,
        entity_id: String,
        reply: SyncSender<Result<Vec<TargetSnapshot>, MiddlewareError>>,
    },
    DefineType {
        schema: TypeSchema,
        reply: SyncSender<Result<(), MiddlewareError>>,
    },
    DefineCustomColumn {
        def: CustomColumnDef,
        reply: SyncSender<Result<(), MiddlewareError>>,
    },
    Flush(SyncSender<Result<(), MiddlewareError>>),
    RedriveDlq(SyncSender<Result<usize, MiddlewareError>>),
    ApplyRetention(SyncSender<Result<usize, MiddlewareError>>),
    DlqLen(SyncSender<Result<usize, MiddlewareError>>),
    VerifyIntegrity(SyncSender<Result<VerifyReport, MiddlewareError>>),
}

/// Cloneable, thread-safe handle the host application talks to. `emit` never
/// blocks and never touches the disk on the caller's thread — persistence
/// happens asynchronously on the dedicated writer thread.
#[derive(Clone)]
pub struct AuditHandle {
    tx: SyncSender<Command>,
    permissions: Arc<PermissionPolicy>,
    metrics: Arc<PipelineMetrics>,
    health: Arc<HealthState>,
    reject_emit_when_disk_full: bool,
}

impl AuditHandle {
    fn check(&self, role: &Role, action: Action) -> Result<(), MiddlewareError> {
        if self.permissions.is_allowed(role, action) {
            Ok(())
        } else {
            Err(MiddlewareError::PermissionDenied {
                role: role.clone(),
                action,
            })
        }
    }

    /// Fire-and-forget: enqueue an audit event. Returns immediately.
    pub fn emit(&self, role: &Role, event: AuditEvent) -> Result<(), MiddlewareError> {
        self.check(role, Action::Emit)?;
        self.emit_unchecked(event)
    }

    /// Enqueue without a permission check (used by the HTTP layer, which has
    /// its own configured emitting identity).
    pub fn emit_unchecked(&self, event: AuditEvent) -> Result<(), MiddlewareError> {
        if self.reject_emit_when_disk_full && self.health.disk_full() {
            self.metrics.rejected_disk_full();
            return Err(MiddlewareError::DiskFull(Box::new(event)));
        }
        // inc before send so the worker's dec (after recv) can never observe
        // the gauge before the inc happened
        self.metrics.queue_inc();
        match self.tx.try_send(Command::Emit(Box::new(event))) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(Command::Emit(ev))) => {
                self.metrics.queue_dec();
                self.metrics.rejected_queue_full();
                Err(MiddlewareError::QueueFull(ev))
            }
            Err(_) => {
                self.metrics.queue_dec();
                Err(MiddlewareError::WorkerGone)
            }
        }
    }

    /// A point-in-time copy of the pipeline counters (queue depth, DLQ size,
    /// write/retry/park/loss counts, write-latency histogram). Reads shared
    /// atomics only — never round-trips the writer thread, so it works even
    /// when the writer is wedged or dead.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// A point-in-time copy of the pipeline health flags (writer liveness,
    /// disk-full latch, low-disk warning). Same liveness guarantee as
    /// [`metrics`](Self::metrics).
    pub fn health(&self) -> HealthSnapshot {
        self.health.snapshot()
    }

    /// The shared health flags themselves — for hosts/tests that need to
    /// drive the state (e.g. simulating a full disk).
    pub fn health_state(&self) -> Arc<HealthState> {
        self.health.clone()
    }

    fn round_trip<T>(
        &self,
        make: impl FnOnce(SyncSender<Result<T, MiddlewareError>>) -> Command,
    ) -> Result<T, MiddlewareError> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(make(reply_tx))
            .map_err(|_| MiddlewareError::WorkerGone)?;
        reply_rx.recv().map_err(|_| MiddlewareError::WorkerGone)?
    }

    /// A point-in-time read snapshot (permission-gated). Taking it costs the
    /// writer thread only a registry-index clone; scans then run wherever the
    /// caller likes, so even slow queries never block event persistence.
    pub fn snapshot(&self, role: &Role) -> Result<ReadSnapshot, MiddlewareError> {
        self.check(role, Action::Query)?;
        self.round_trip(Command::Snapshot).map(|b| *b)
    }

    /// Query recorded logs (permission-gated). The scan runs on the *calling*
    /// thread against a read snapshot — the writer thread keeps persisting
    /// events meanwhile. In async code wrap it in `spawn_blocking`.
    pub fn query(&self, role: &Role, q: LogQuery) -> Result<Vec<LogView>, MiddlewareError> {
        self.snapshot(role)?
            .query(&q)
            .map_err(MiddlewareError::Core)
    }

    /// Schemas of all defined entity/actor types (permission-gated).
    pub fn entity_types(&self, role: &Role) -> Result<Vec<TypeSchema>, MiddlewareError> {
        self.check(role, Action::Query)?;
        self.round_trip(Command::EntityTypes)
    }

    /// Latest version of every entity of a type (permission-gated).
    pub fn list_entities(
        &self,
        role: &Role,
        type_name: impl Into<String>,
        include_deleted: bool,
    ) -> Result<Vec<TargetSnapshot>, MiddlewareError> {
        self.check(role, Action::Query)?;
        let type_name = type_name.into();
        self.round_trip(|reply| Command::ListEntities {
            type_name,
            include_deleted,
            reply,
        })
    }

    /// Full version history of one entity, oldest first (permission-gated).
    pub fn entity_history(
        &self,
        role: &Role,
        type_name: impl Into<String>,
        entity_id: impl Into<String>,
    ) -> Result<Vec<TargetSnapshot>, MiddlewareError> {
        self.check(role, Action::Query)?;
        let (type_name, entity_id) = (type_name.into(), entity_id.into());
        self.round_trip(|reply| Command::EntityHistory {
            type_name,
            entity_id,
            reply,
        })
    }

    /// Create (or additively redefine) the registry table for an entity/actor
    /// type (permission-gated, [`Action::Administer`]). Server-mode clients
    /// need this — in embedded mode the host defines types before the
    /// pipeline starts, but a remote client only ever talks to the handle.
    pub fn define_type(&self, role: &Role, schema: TypeSchema) -> Result<(), MiddlewareError> {
        self.check(role, Action::Administer)?;
        self.round_trip(|reply| Command::DefineType { schema, reply })
    }

    /// Register an extra audit-log column (permission-gated,
    /// [`Action::Administer`]) — see [`AuditStore::define_custom_column`].
    pub fn define_custom_column(
        &self,
        role: &Role,
        def: CustomColumnDef,
    ) -> Result<(), MiddlewareError> {
        self.check(role, Action::Administer)?;
        self.round_trip(|reply| Command::DefineCustomColumn { def, reply })
    }

    /// Wait until every event enqueued so far is durably on disk.
    pub fn flush(&self) -> Result<(), MiddlewareError> {
        self.round_trip(Command::Flush)
    }

    /// Replay parked DLQ events into the store. Returns how many succeeded.
    pub fn redrive_dlq(&self, role: &Role) -> Result<usize, MiddlewareError> {
        self.check(role, Action::Administer)?;
        self.round_trip(Command::RedriveDlq)
    }

    /// Enforce the retention window now. Returns segments dropped.
    pub fn apply_retention(&self, role: &Role) -> Result<usize, MiddlewareError> {
        self.check(role, Action::Administer)?;
        self.round_trip(Command::ApplyRetention)
    }

    pub fn dlq_len(&self, role: &Role) -> Result<usize, MiddlewareError> {
        self.check(role, Action::Administer)?;
        self.round_trip(Command::DlqLen)
    }

    /// Verify the store's tamper-evidence hash chains (permission-gated,
    /// [`Action::Administer`]). A found chain break comes back as a
    /// [`VerifyReport`] with `ok: false`, not as `Err` — `Err` means the
    /// verification itself could not be run.
    ///
    /// This is a full-store scan and it runs **on the writer thread** (the
    /// core API needs `&mut` store access): while it runs, emits queue up in
    /// the bounded channel instead of being persisted. Callers should make
    /// sure only one verification runs at a time and call this from a
    /// blocking-friendly context (`spawn_blocking` in async code).
    pub fn verify_integrity(&self, role: &Role) -> Result<VerifyReport, MiddlewareError> {
        self.check(role, Action::Administer)?;
        self.round_trip(Command::VerifyIntegrity)
    }
}

/// Owns the writer thread. Keep it alive as long as auditing should run; call
/// [`shutdown`](AuditPipeline::shutdown) for a clean, fully-flushed stop.
pub struct AuditPipeline {
    handle: AuditHandle,
    join: Option<std::thread::JoinHandle<()>>,
}

impl AuditPipeline {
    /// Spawn the writer thread around an opened store.
    pub fn start(
        store: AuditStore,
        store_root: PathBuf,
        permissions: PermissionPolicy,
        cfg: PipelineConfig,
        fallback: Option<FallbackFn>,
    ) -> Result<Self, MiddlewareError> {
        let dlq_dir = cfg
            .dlq_dir
            .clone()
            .unwrap_or_else(|| store_root.join("dlq"));
        // finish an interrupted redrive swap: if the crash hit after the old
        // DLQ dir was removed but before the rebuilt one was renamed into
        // place, the rebuilt dir is authoritative; if both exist, the old dir
        // is (the rebuilt one may be missing late failures) and the leftover
        // is discarded
        let staging = redrive_staging_dir(&dlq_dir);
        if staging.exists() {
            if dlq_dir.exists() {
                std::fs::remove_dir_all(&staging).map_err(|e| MiddlewareError::Core(e.into()))?;
            } else {
                std::fs::rename(&staging, &dlq_dir).map_err(|e| MiddlewareError::Core(e.into()))?;
            }
        }
        let mut dlq: Table<DlqEntry> =
            Table::open(&dlq_dir, DLQ_SEGMENT_BYTES).map_err(MiddlewareError::Core)?;
        let metrics = Arc::new(PipelineMetrics::default());
        let health = Arc::new(HealthState::new(cfg.disk_thresholds));
        // seed the DLQ gauge with what survived the restart
        let parked = dlq
            .scan()
            .map_err(MiddlewareError::Core)?
            .filter(|r| r.is_ok())
            .count();
        metrics.set_dlq_entries(parked as u64);
        let (tx, rx) = sync_channel(cfg.queue_capacity);
        let worker = Worker {
            store,
            store_root,
            dlq: Some(dlq),
            dlq_dir,
            cfg: cfg.clone(),
            fallback,
            metrics: metrics.clone(),
            health: health.clone(),
        };
        let join = std::thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || worker.run(rx))
            .map_err(|e| MiddlewareError::Core(quipu_core::Error::Io(e)))?;
        Ok(Self {
            handle: AuditHandle {
                tx,
                permissions: Arc::new(permissions),
                metrics,
                health,
                reject_emit_when_disk_full: cfg.reject_emit_when_disk_full,
            },
            join: Some(join),
        })
    }

    pub fn handle(&self) -> AuditHandle {
        self.handle.clone()
    }

    /// Flush everything queued so far and stop the writer thread. Safe to call
    /// while [`AuditHandle`] clones are still alive elsewhere — their emits
    /// will fail with [`MiddlewareError::WorkerGone`] afterwards.
    pub fn shutdown(mut self) {
        let (ack_tx, ack_rx) = sync_channel(1);
        if self.handle.tx.send(Command::Shutdown(ack_tx)).is_ok() {
            let _ = ack_rx.recv();
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for AuditPipeline {
    fn drop(&mut self) {
        self.join.take(); // detach; worker exits when all handles drop
    }
}

const DLQ_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;

fn redrive_staging_dir(dlq_dir: &std::path::Path) -> PathBuf {
    dlq_dir.with_extension("redrive")
}

/// Collect every `seg-*.log` table segment under `root`, skipping the DLQ
/// (and its redrive staging twin) — the DLQ is not part of the verified
/// store. The name pattern mirrors quipu-core's on-disk table layout; it is
/// only used for the report's `segments_checked` count.
fn collect_segment_files(root: &Path, dlq_dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path == dlq_dir || path == redrive_staging_dir(dlq_dir) {
                continue;
            }
            collect_segment_files(&path, dlq_dir, out);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".log"))
        {
            out.push(path);
        }
    }
}

/// Count the rows readable in the audit-log table right now. Runs on the
/// worker thread straight after verification, so no append can race the
/// scan. A row that fails to decode stops the count (it is also a `problem`
/// in the report) — the number then reads as "records intact up to the
/// break".
fn count_log_records(root: &Path) -> usize {
    let mut segments = Vec::new();
    let logs_dir = root.join("logs");
    if let Ok(entries) = std::fs::read_dir(&logs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".log"))
            {
                segments.push(path);
            }
        }
    }
    segments.sort();
    let slices = segments
        .into_iter()
        .map(|path| SegmentSlice {
            path,
            bound: u64::MAX,
        })
        .collect();
    TableScan::<AuditLog>::over(slices)
        .map_while(|r| r.ok())
        .count()
}

struct Worker {
    store: AuditStore,
    /// Store directory — used by verification to count segment files.
    store_root: PathBuf,
    /// `None` only transiently, mid-redrive-swap or after a failed reopen;
    /// [`Worker::dlq`] lazily reopens in that case.
    dlq: Option<Table<DlqEntry>>,
    dlq_dir: PathBuf,
    cfg: PipelineConfig,
    fallback: Option<FallbackFn>,
    metrics: Arc<PipelineMetrics>,
    health: Arc<HealthState>,
}

/// Flips `writer_alive` to false when the worker leaves `run()` — including
/// by panic, which is exactly the death health checks must be able to see.
struct AliveGuard(Arc<HealthState>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.set_writer_alive(false);
    }
}

impl Worker {
    fn run(mut self, rx: Receiver<Command>) {
        let _alive = AliveGuard(self.health.clone());
        let mut shutdown_ack = None;
        loop {
            match rx.recv_timeout(self.cfg.housekeeping_interval) {
                Ok(Command::Shutdown(ack)) => {
                    // drain whatever is already queued, then stop
                    while let Ok(cmd) = rx.try_recv() {
                        if !matches!(cmd, Command::Shutdown(_)) {
                            self.handle(cmd);
                        }
                    }
                    shutdown_ack = Some(ack);
                    break;
                }
                Ok(cmd) => self.handle(cmd),
                Err(RecvTimeoutError::Timeout) => self.housekeeping(),
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = self.store.sync();
        if let Some(dlq) = self.dlq.as_mut() {
            let _ = dlq.sync();
        }
        tracing::info!("audit writer stopped");
        if let Some(ack) = shutdown_ack {
            let _ = ack.send(());
        }
    }

    fn handle(&mut self, cmd: Command) {
        match cmd {
            Command::Emit(event) => {
                self.metrics.queue_dec();
                self.write_event(*event);
            }
            Command::Shutdown(_) => unreachable!("handled in run()"),
            Command::Snapshot(reply) => {
                let res = self
                    .store
                    .snapshot()
                    .map(Box::new)
                    .map_err(MiddlewareError::Core);
                let _ = reply.send(res);
            }
            Command::EntityTypes(reply) => {
                let _ = reply.send(Ok(self.store.type_schemas()));
            }
            Command::ListEntities {
                type_name,
                include_deleted,
                reply,
            } => {
                let res = self
                    .store
                    .list_entities(&type_name, include_deleted)
                    .map_err(MiddlewareError::Core);
                let _ = reply.send(res);
            }
            Command::EntityHistory {
                type_name,
                entity_id,
                reply,
            } => {
                let res = self
                    .store
                    .entity_history(&type_name, &entity_id)
                    .map_err(MiddlewareError::Core);
                let _ = reply.send(res);
            }
            Command::DefineType { schema, reply } => {
                let res = self
                    .store
                    .define_type(schema)
                    .map_err(MiddlewareError::Core);
                let _ = reply.send(res);
            }
            Command::DefineCustomColumn { def, reply } => {
                let res = self
                    .store
                    .define_custom_column(def)
                    .map_err(MiddlewareError::Core);
                let _ = reply.send(res);
            }
            Command::Flush(reply) => {
                let res = self.store.sync().map_err(MiddlewareError::Core);
                let _ = reply.send(res);
            }
            Command::RedriveDlq(reply) => {
                let _ = reply.send(self.redrive());
            }
            Command::ApplyRetention(reply) => {
                let _ = reply.send(self.store.apply_retention().map_err(MiddlewareError::Core));
            }
            Command::DlqLen(reply) => {
                let res = (|| {
                    let entries = self
                        .dlq()
                        .and_then(|dlq| dlq.scan())
                        .map_err(MiddlewareError::Core)?;
                    Ok(entries.filter(|r| r.is_ok()).count())
                })();
                if let Ok(n) = &res {
                    // an exact count just happened; sync the gauge to it
                    self.metrics.set_dlq_entries(*n as u64);
                }
                let _ = reply.send(res);
            }
            Command::VerifyIntegrity(reply) => {
                let _ = reply.send(Ok(self.verify()));
            }
        }
    }

    /// Recompute every table's hash chain (logs, relations, meta,
    /// registries) and report what was checked. A chain break or read error
    /// becomes a `problem` in the report instead of failing the call — the
    /// caller wants "is the store intact?", and "could not even read it" is
    /// just the loudest possible "no".
    fn verify(&mut self) -> VerifyReport {
        let problems = match self.store.verify_integrity() {
            Ok(()) => Vec::new(),
            Err(e) => vec![e.to_string()],
        };
        let mut segments = Vec::new();
        collect_segment_files(&self.store_root, &self.dlq_dir, &mut segments);
        let log_records = count_log_records(&self.store_root);
        VerifyReport {
            ok: problems.is_empty(),
            segments_checked: segments.len(),
            log_records,
            problems,
        }
    }

    /// Lazily (re)open the DLQ table — it is detached briefly during the
    /// redrive directory swap.
    fn dlq(&mut self) -> quipu_core::Result<&mut Table<DlqEntry>> {
        if self.dlq.is_none() {
            self.dlq = Some(Table::open(&self.dlq_dir, DLQ_SEGMENT_BYTES)?);
        }
        Ok(self.dlq.as_mut().expect("just opened"))
    }

    fn try_write(&mut self, event: &AuditEvent) -> Result<Uid, quipu_core::Error> {
        let targets: Vec<(String, quipu_core::EntityInput)> = event
            .targets
            .iter()
            .map(|t| (t.entity_type.clone(), t.input.clone()))
            .collect();
        self.store.append_at(
            event.occurred_at,
            &event.actor_type,
            &event.actor,
            &event.method,
            &event.url,
            event.content.clone(),
            &targets,
            event.custom.clone(),
        )
    }

    /// Persist one event with retries; park it in the DLQ on final failure.
    /// Every outcome is logged (the "result logging" surface) and counted
    /// (the metrics surface).
    ///
    /// ENOSPC short-circuits the retry loop: disk-full is a persistent
    /// condition, so backing off and rewriting the same bytes can only fail
    /// again — the event goes straight to [`park`](Self::park) (whose DLQ
    /// write usually also fails on the same disk, which is what the fallback
    /// hook is for) and the disk-full latch is set for health/fast-reject.
    fn write_event(&mut self, event: AuditEvent) {
        let started = std::time::Instant::now();
        let mut last_err = String::new();
        for attempt in 0..=self.cfg.max_retries {
            match self.try_write(&event) {
                Ok(log_id) => {
                    self.metrics.write_ok(started.elapsed());
                    if self.health.set_disk_full(false) {
                        tracing::info!("audit store writable again; disk-full latch cleared");
                    }
                    tracing::debug!(%log_id, method = %event.method, url = %event.url, "audit log written");
                    return;
                }
                Err(e) if e.is_storage_full() => {
                    last_err = e.to_string();
                    if !self.health.set_disk_full(true) {
                        tracing::error!(error = %last_err, "audit store disk is FULL; suspending retries");
                    }
                    break;
                }
                Err(e) => {
                    last_err = e.to_string();
                    tracing::warn!(attempt, error = %last_err, "audit write failed");
                    if attempt < self.cfg.max_retries {
                        self.metrics.retry();
                        std::thread::sleep(self.cfg.retry_backoff);
                    }
                }
            }
        }
        self.park(event, last_err);
    }

    fn park(&mut self, event: AuditEvent, error: String) {
        self.metrics.parked();
        let entry = DlqEntry {
            event,
            error: error.clone(),
            failed_at: quipu_core::time::now_micros(),
        };
        let dlq_result = self.dlq().and_then(|dlq| {
            dlq.append(&entry, entry.failed_at)?;
            dlq.sync()
        });
        match dlq_result {
            Ok(()) => {
                self.metrics.dlq_inc();
                tracing::error!(error = %error, "audit event parked in dead-letter queue");
                if let Some(fb) = &self.fallback {
                    fb(&entry.event, &error);
                }
            }
            Err(dlq_err) => {
                self.metrics.lost();
                if dlq_err.is_storage_full() && !self.health.set_disk_full(true) {
                    tracing::error!("DLQ disk is FULL; disk-full latch set");
                }
                // last line of defense: the fallback hook and the error log
                tracing::error!(error = %error, dlq_error = %dlq_err, "audit event LOST (store and DLQ both failed)");
                if let Some(fb) = &self.fallback {
                    fb(
                        &entry.event,
                        &format!("{error}; dlq also failed: {dlq_err}"),
                    );
                }
            }
        }
    }

    /// Replay every DLQ entry. Entries that fail again are re-parked.
    ///
    /// Crash safety: failures are first written to a *staging* table and made
    /// durable; only then is the old DLQ directory removed and the staging
    /// directory renamed into its place. The old "clear, then re-append"
    /// order lost every parked event if the process died in between. A crash
    /// before the swap leaves the old DLQ intact (some events may later be
    /// written twice — at-least-once, the right trade-off for audit data); a
    /// crash inside the swap is finished by [`AuditPipeline::start`].
    fn redrive(&mut self) -> Result<usize, MiddlewareError> {
        let entries: Vec<DlqEntry> = self
            .dlq()
            .and_then(|dlq| dlq.scan())
            .map_err(MiddlewareError::Core)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(MiddlewareError::Core)?;
        if entries.is_empty() {
            return Ok(0);
        }
        let staging_dir = redrive_staging_dir(&self.dlq_dir);
        if staging_dir.exists() {
            std::fs::remove_dir_all(&staging_dir).map_err(|e| MiddlewareError::Core(e.into()))?;
        }
        let mut staging: Table<DlqEntry> =
            Table::open(&staging_dir, DLQ_SEGMENT_BYTES).map_err(MiddlewareError::Core)?;
        let total = entries.len();
        let mut ok = 0;
        for entry in entries {
            match self.try_write(&entry.event) {
                Ok(_) => ok += 1,
                Err(e) => {
                    let error = e.to_string();
                    tracing::error!(error = %error, "redriven audit event failed again, re-parked");
                    let entry = DlqEntry {
                        event: entry.event,
                        error: error.clone(),
                        failed_at: quipu_core::time::now_micros(),
                    };
                    staging
                        .append(&entry, entry.failed_at)
                        .map_err(MiddlewareError::Core)?;
                    if let Some(fb) = &self.fallback {
                        fb(&entry.event, &error);
                    }
                }
            }
        }
        // make both the successful writes and the re-parked failures durable
        // before the old DLQ is destroyed
        self.store.sync().map_err(MiddlewareError::Core)?;
        staging.sync().map_err(MiddlewareError::Core)?;
        drop(staging);
        self.dlq = None; // close our handle before touching the directories
        std::fs::remove_dir_all(&self.dlq_dir).map_err(|e| MiddlewareError::Core(e.into()))?;
        std::fs::rename(&staging_dir, &self.dlq_dir)
            .map_err(|e| MiddlewareError::Core(e.into()))?;
        self.dlq().map_err(MiddlewareError::Core)?;
        self.metrics.set_dlq_entries((total - ok) as u64);
        Ok(ok)
    }

    fn housekeeping(&mut self) {
        if let Err(e) = self.store.sync() {
            tracing::error!(error = %e, "periodic sync failed");
        }
        match self.store.apply_retention() {
            Ok(0) => {}
            Ok(n) => tracing::info!(segments = n, "retention dropped old segments"),
            Err(e) => tracing::error!(error = %e, "retention failed"),
        }
        self.check_disk();
    }

    /// Measure free space under the store root, maintain the `low_disk`
    /// early warning and release the disk-full latch once space is back
    /// above the warning thresholds (the other release path is a write
    /// simply succeeding again).
    ///
    /// The warning fires once per transition into low-disk — as a `warn` log
    /// line *and* through the fallback hook (with a synthetic `system` event,
    /// `url = "quipu://disk-space-low"`), so the same channel that hears
    /// about lost events hears the early warning too.
    fn check_disk(&mut self) {
        let usage = match disk_usage(&self.store_root) {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!(error = %e, "disk usage measurement failed");
                return;
            }
        };
        let low = self.health.thresholds().is_low(&usage);
        let was_low = self.health.set_low_disk(low);
        if low && !was_low {
            let msg = format!(
                "disk space low under audit store root: {} free of {} bytes",
                usage.free_bytes, usage.total_bytes
            );
            tracing::warn!(
                free_bytes = usage.free_bytes,
                total_bytes = usage.total_bytes,
                "{msg}"
            );
            if let Some(fb) = &self.fallback {
                let alert = AuditEvent::new(
                    "system",
                    quipu_core::EntityInput::new("quipu-pipeline"),
                    "ALERT",
                    "quipu://disk-space-low",
                    quipu_core::Content::Text(msg.clone()),
                );
                fb(&alert, &msg);
            }
        } else if !low && was_low {
            tracing::info!(
                free_bytes = usage.free_bytes,
                "disk space back above thresholds"
            );
        }
        if !low && self.health.disk_full() && self.health.set_disk_full(false) {
            tracing::info!("free space recovered; disk-full latch cleared");
        }
    }
}
