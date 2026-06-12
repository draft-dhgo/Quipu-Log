use crate::auth::{role_for, AuthState};
use crate::config::ServerConfig;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use quipu_core::{Content, CustomColumnDef, EntityInput, LogQuery, TypeSchema, Value};
use quipu_middleware::{
    disk_usage, Action, AuditEvent, AuditHandle, DiskUsage, HealthSnapshot, MetricsSnapshot,
    MiddlewareError, Role, TargetSpec, VerifyReport,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct AppState {
    pub handle: AuditHandle,
    /// Store root directory — health probes write here, `/metrics` sizes it.
    store_root: Arc<PathBuf>,
    /// Hot-reloadable auth view (tokens + grants + query cap). All
    /// permission gating happens here at the HTTP layer — the pipeline runs
    /// `allow_all` in this binary precisely so a SIGHUP reload of this field
    /// is the single source of truth.
    auth: Arc<RwLock<AuthState>>,
    /// Per-token-hash query semaphores, created lazily; cleared on reload so
    /// a changed cap takes effect (in-flight permits stay on the old
    /// semaphores and just drain out).
    query_slots: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    /// True while an integrity verification runs. Verification is a
    /// full-store scan on the writer thread, so the endpoint and the periodic
    /// task share this guard to keep it to one pass at a time.
    verify_running: Arc<AtomicBool>,
    /// Completed verification passes since startup (endpoint + periodic) —
    /// an observability counter, also what tests poll.
    verify_runs: Arc<AtomicU64>,
}

/// One reserved unit of a token's concurrent-query budget.
pub enum QuerySlot {
    /// No `max_concurrent_queries` configured.
    Unlimited,
    /// Slot held until the permit drops.
    Acquired(OwnedSemaphorePermit),
    /// Budget exhausted — the HTTP layer answers 429.
    Busy,
}

impl AppState {
    pub fn new(handle: AuditHandle, auth: AuthState, store_root: PathBuf) -> Self {
        Self {
            handle,
            store_root: Arc::new(store_root),
            auth: Arc::new(RwLock::new(auth)),
            query_slots: Arc::new(Mutex::new(HashMap::new())),
            verify_running: Arc::new(AtomicBool::new(false)),
            verify_runs: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Claim the single verification slot. `None` while a verification is
    /// already running (the HTTP layer answers 409); the slot frees itself
    /// when the returned guard drops. Public so tests can occupy it
    /// deterministically.
    pub fn try_begin_verify(&self) -> Option<VerifyGuard> {
        self.verify_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then(|| VerifyGuard(self.verify_running.clone()))
    }

    /// Verification passes completed since startup (endpoint + periodic).
    pub fn verify_runs(&self) -> u64 {
        self.verify_runs.load(Ordering::Acquire)
    }

    /// Re-read `path` and swap in its `auth` section. On any error (I/O,
    /// parse, bad token hash) the previous auth state stays in force — a
    /// botched edit must not lock everyone out of a running server.
    pub fn reload_auth(&self, path: &std::path::Path) -> std::io::Result<()> {
        let cfg = ServerConfig::load(path)?;
        let next = cfg.auth_state()?;
        let mut auth = self.auth.write().unwrap();
        // hash-level diff doubles as the issue/revoke audit trail in the
        // server log, without ever logging token material
        let added = next
            .tokens
            .hashes()
            .filter(|h| !auth.tokens.contains_hash(h))
            .count();
        let removed = auth
            .tokens
            .hashes()
            .filter(|h| !next.tokens.contains_hash(h))
            .count();
        if next.max_concurrent_queries != auth.max_concurrent_queries {
            self.query_slots.lock().unwrap().clear();
        }
        *auth = next;
        tracing::info!(
            tokens_added = added,
            tokens_removed = removed,
            "auth section reloaded"
        );
        Ok(())
    }

    /// Reserve one of the token's concurrent-query slots, keyed by the
    /// token's SHA-256 hex (see [`crate::auth::sha256_hex`]). Public so tests can occupy
    /// a slot deterministically.
    pub fn query_slot(&self, token_hash: &str) -> QuerySlot {
        let limit = self.auth.read().unwrap().max_concurrent_queries;
        let Some(limit) = limit else {
            return QuerySlot::Unlimited;
        };
        let semaphore = self
            .query_slots
            .lock()
            .unwrap()
            .entry(token_hash.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(limit as usize)))
            .clone();
        match semaphore.try_acquire_owned() {
            Ok(permit) => QuerySlot::Acquired(permit),
            Err(_) => QuerySlot::Busy,
        }
    }
}

/// The claimed verification slot (see [`AppState::try_begin_verify`]);
/// dropping it lets the next verification start.
pub struct VerifyGuard(Arc<AtomicBool>);

impl Drop for VerifyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/v1/types", post(define_type).get(list_types))
        .route("/v1/columns", post(define_column))
        .route("/v1/logs", post(append_log))
        .route("/v1/logs/query", post(query_logs))
        .route("/v1/entities/{type_name}", get(list_entities))
        .route(
            "/v1/entities/{type_name}/{entity_id}/history",
            get(entity_history),
        )
        .route("/v1/admin/flush", post(admin_flush))
        .route("/v1/admin/redrive", post(admin_redrive))
        .route("/v1/admin/retention", post(admin_retention))
        .route("/v1/admin/dlq", get(admin_dlq))
        .route("/v1/admin/verify", post(admin_verify))
        .with_state(state)
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

impl From<MiddlewareError> for ApiError {
    fn from(e: MiddlewareError) -> Self {
        let status = match &e {
            MiddlewareError::PermissionDenied { .. } => StatusCode::FORBIDDEN,
            // the event is handed back inside the error; the HTTP client's
            // retry (after backoff) is the equivalent of re-emitting it
            MiddlewareError::QueueFull(_) => StatusCode::SERVICE_UNAVAILABLE,
            // persistent until space is freed — retrying immediately is
            // pointless, so a distinct status the client can back off on
            MiddlewareError::DiskFull(_) => StatusCode::INSUFFICIENT_STORAGE,
            MiddlewareError::WorkerGone => StatusCode::INTERNAL_SERVER_ERROR,
            MiddlewareError::Core(core) => match core {
                quipu_core::Error::Schema(_) | quipu_core::Error::Crypto(_) => {
                    StatusCode::BAD_REQUEST
                }
                quipu_core::Error::NotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        };
        ApiError {
            status,
            message: e.to_string(),
        }
    }
}

fn unauthorized() -> ApiError {
    ApiError {
        status: StatusCode::UNAUTHORIZED,
        message: "missing or unknown bearer token".into(),
    }
}

fn internal(msg: impl Into<String>) -> ApiError {
    ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: msg.into(),
    }
}

struct Caller {
    role: Role,
    /// SHA-256 hex of the presented token — the per-token rate-limit key.
    token_hash: String,
}

impl AppState {
    /// Authenticate the bearer token (existence + expiry) and check the
    /// role's grant in one step, against the current (possibly reloaded)
    /// auth state.
    fn authorize(&self, headers: &HeaderMap, action: Action) -> Result<Caller, ApiError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before 1970")
            .as_secs();
        let auth = self.auth.read().unwrap();
        let (role, token_hash) = role_for(headers, &auth.tokens, now).ok_or_else(unauthorized)?;
        if !auth.policy.is_allowed(&role, action) {
            return Err(MiddlewareError::PermissionDenied { role, action }.into());
        }
        Ok(Caller { role, token_hash })
    }
}

/// Run a handle call that blocks on the writer thread (or scans segments) off
/// the async runtime.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, MiddlewareError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(format!("worker task failed: {e}")))?
        .map_err(ApiError::from)
}

// ---- health ------------------------------------------------------------------

/// `GET /v1/healthz` — unauthenticated, JSON
/// `{"status": "ok"|"degraded"|"unhealthy", "reasons": [...]}`.
///
/// - `unhealthy` (HTTP 503): the writer thread is dead, the disk-full latch
///   is set, or a probe write into the store root fails — appends are not
///   being persisted.
/// - `degraded` (HTTP 200): writes still work but free disk space is below
///   the configured thresholds (act now, before it becomes 503).
/// - `ok` (HTTP 200).
///
/// (Pre-observability versions answered plain-text `ok` unconditionally;
/// monitors matching on the body must switch to the status code or JSON.)
async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let snapshot = state.handle.health();
    let root = state.store_root.clone();
    // the probe write and statvfs touch the filesystem: off the async runtime
    let report = tokio::task::spawn_blocking(move || evaluate_health(&snapshot, &root)).await;
    match report {
        Ok(report) => report.into_response_parts(),
        Err(e) => {
            HealthReport::unhealthy(format!("health check task failed: {e}")).into_response_parts()
        }
    }
}

/// Outcome of one health evaluation (separated from the handler so tests can
/// drive it with synthetic snapshots).
pub struct HealthReport {
    pub status: &'static str,
    pub reasons: Vec<String>,
}

impl HealthReport {
    fn unhealthy(reason: String) -> Self {
        Self {
            status: "unhealthy",
            reasons: vec![reason],
        }
    }

    fn into_response_parts(self) -> (StatusCode, Json<serde_json::Value>) {
        let code = if self.status == "unhealthy" {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            // degraded stays 200: load balancers must not eject an instance
            // that is still persisting events — the body carries the warning
            StatusCode::OK
        };
        (
            code,
            Json(serde_json::json!({ "status": self.status, "reasons": self.reasons })),
        )
    }
}

/// Combine the pipeline's health flags with live filesystem checks:
/// writer liveness and the disk-full latch from the snapshot, plus a probe
/// write into the store root (is the directory actually writable *now*?) and
/// a fresh statvfs against the configured thresholds.
pub fn evaluate_health(snapshot: &HealthSnapshot, store_root: &FsPath) -> HealthReport {
    let mut reasons = Vec::new();
    let mut unhealthy = false;
    let mut degraded = false;
    if !snapshot.writer_alive {
        unhealthy = true;
        reasons.push("audit writer thread is not running".into());
    }
    if snapshot.disk_full {
        unhealthy = true;
        reasons.push("store disk is full (writes are failing with ENOSPC)".into());
    }
    if let Err(e) = probe_write(store_root) {
        unhealthy = true;
        reasons.push(format!("store root is not writable: {e}"));
    }
    match disk_usage(store_root) {
        Ok(usage) => {
            if snapshot.thresholds.is_low(&usage) {
                degraded = true;
                reasons.push(format!(
                    "free disk space low: {} of {} bytes free (thresholds: {} bytes / {:.0}%)",
                    usage.free_bytes,
                    usage.total_bytes,
                    snapshot.thresholds.min_free_bytes,
                    snapshot.thresholds.min_free_ratio * 100.0
                ));
            }
        }
        // measurement unsupported/failed: fall back to the writer's last
        // housekeeping verdict instead of crying wolf
        Err(_) => {
            if snapshot.low_disk {
                degraded = true;
                reasons.push("free disk space low (reported by pipeline housekeeping)".into());
            }
        }
    }
    let status = if unhealthy {
        "unhealthy"
    } else if degraded {
        "degraded"
    } else {
        "ok"
    };
    HealthReport { status, reasons }
}

/// Create, write, fsync and remove a small probe file in the store root —
/// the most direct answer to "can the store still take bytes?".
fn probe_write(store_root: &FsPath) -> std::io::Result<()> {
    let path = store_root.join(".healthz-probe");
    let result = (|| {
        let mut f = std::fs::File::create(&path)?;
        std::io::Write::write_all(&mut f, b"probe")?;
        f.sync_all()
    })();
    let _ = std::fs::remove_file(&path); // best effort either way
    result
}

// ---- metrics -----------------------------------------------------------------

/// `GET /metrics` — Prometheus text exposition of the pipeline counters plus
/// store/disk gauges. Requires a bearer token with `Administer`, like the
/// other operational endpoints (point Prometheus at it with
/// `authorization: { credentials: <token> }`).
async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    state.authorize(&headers, Action::Administer)?;
    let snapshot = state.handle.metrics();
    let health = state.handle.health();
    let verify_runs = state.verify_runs();
    let root = state.store_root.clone();
    // dir walk + statvfs: off the async runtime
    let body = tokio::task::spawn_blocking(move || {
        let store_bytes = dir_size(&root);
        let disk = disk_usage(&root).ok();
        render_prometheus(&snapshot, &health, store_bytes, disk, verify_runs)
    })
    .await
    .map_err(|e| internal(format!("metrics task failed: {e}")))?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response())
}

/// Total bytes of all files under `root` (the whole store: logs, relations,
/// registries, meta, checkpoints, DLQ). Unreadable entries count as 0 — a
/// metric scrape must not fail over a transient unlink race.
fn dir_size(root: &FsPath) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            total += dir_size(&path);
        } else {
            total += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

/// Hand-rolled Prometheus text format (v0.0.4) — the counter set is small
/// and fixed, so a real metrics framework would be all dependency and no
/// benefit.
pub fn render_prometheus(
    m: &MetricsSnapshot,
    h: &HealthSnapshot,
    store_bytes: u64,
    disk: Option<DiskUsage>,
    verify_runs: u64,
) -> String {
    fn metric_into(out: &mut String, name: &str, kind: &str, help: &str, value: String) {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        let _ = writeln!(out, "{name} {value}");
    }
    let mut out = String::with_capacity(2048);
    let metric = metric_into;
    metric(
        &mut out,
        "quipu_queue_depth",
        "gauge",
        "Audit events enqueued but not yet picked up by the writer thread.",
        m.queue_depth.to_string(),
    );
    metric(
        &mut out,
        "quipu_dlq_entries",
        "gauge",
        "Events currently parked in the dead-letter queue.",
        m.dlq_entries.to_string(),
    );
    metric(
        &mut out,
        "quipu_writes_ok_total",
        "counter",
        "Events durably appended to the store.",
        m.writes_ok.to_string(),
    );
    metric(
        &mut out,
        "quipu_write_retries_total",
        "counter",
        "Failed write attempts that were retried.",
        m.write_retries.to_string(),
    );
    metric(
        &mut out,
        "quipu_writes_parked_total",
        "counter",
        "Events that exhausted retries (or hit disk-full) and went to the DLQ.",
        m.writes_parked.to_string(),
    );
    metric(
        &mut out,
        "quipu_events_lost_total",
        "counter",
        "Events lost outright: store and DLQ both failed (fallback hook only).",
        m.events_lost.to_string(),
    );
    let _ = writeln!(
        out,
        "# HELP quipu_emit_rejected_total Emits rejected at the caller, by reason.\n\
         # TYPE quipu_emit_rejected_total counter\n\
         quipu_emit_rejected_total{{reason=\"queue_full\"}} {}\n\
         quipu_emit_rejected_total{{reason=\"disk_full\"}} {}",
        m.emit_rejected_queue_full, m.emit_rejected_disk_full
    );
    let _ = writeln!(
        out,
        "# HELP quipu_write_latency_seconds Wall time to durably persist one event (including retries).\n\
         # TYPE quipu_write_latency_seconds histogram"
    );
    for (bound, count) in &m.write_latency.buckets {
        let _ = writeln!(
            out,
            "quipu_write_latency_seconds_bucket{{le=\"{bound}\"}} {count}"
        );
    }
    let _ = writeln!(
        out,
        "quipu_write_latency_seconds_bucket{{le=\"+Inf\"}} {}\n\
         quipu_write_latency_seconds_sum {}\n\
         quipu_write_latency_seconds_count {}",
        m.write_latency.count, m.write_latency.sum_seconds, m.write_latency.count
    );
    metric(
        &mut out,
        "quipu_store_bytes",
        "gauge",
        "Total bytes on disk under the store root (all tables, registries, DLQ).",
        store_bytes.to_string(),
    );
    if let Some(d) = disk {
        metric(
            &mut out,
            "quipu_disk_free_bytes",
            "gauge",
            "Free bytes on the filesystem holding the store root.",
            d.free_bytes.to_string(),
        );
        metric(
            &mut out,
            "quipu_disk_total_bytes",
            "gauge",
            "Size of the filesystem holding the store root.",
            d.total_bytes.to_string(),
        );
    }
    metric(
        &mut out,
        "quipu_writer_alive",
        "gauge",
        "1 while the audit writer thread is running.",
        u8::from(h.writer_alive).to_string(),
    );
    metric(
        &mut out,
        "quipu_disk_full",
        "gauge",
        "1 while the ENOSPC latch is set (writes failing for lack of space).",
        u8::from(h.disk_full).to_string(),
    );
    metric(
        &mut out,
        "quipu_disk_low",
        "gauge",
        "1 while free disk space is below the warning thresholds.",
        u8::from(h.low_disk).to_string(),
    );
    metric(
        &mut out,
        "quipu_verify_runs_total",
        "counter",
        "Completed integrity verification passes since startup.",
        verify_runs.to_string(),
    );
    out
}

// ---- schema ----------------------------------------------------------------

async fn define_type(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(schema): Json<TypeSchema>,
) -> Result<StatusCode, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    blocking(move || handle.define_type(&role, schema)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_types(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TypeSchema>>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let handle = state.handle.clone();
    Ok(Json(blocking(move || handle.entity_types(&role)).await?))
}

async fn define_column(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(def): Json<CustomColumnDef>,
) -> Result<StatusCode, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    blocking(move || handle.define_custom_column(&role, def)).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- logs --------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendRequest {
    /// UTC-micros event time; defaults to "now" on the server. Senders that
    /// queue/retry should set it so the log records when the action happened.
    occurred_at: Option<u64>,
    actor_type: String,
    actor: EntityInput,
    method: String,
    url: String,
    content: Content,
    #[serde(default)]
    targets: Vec<TargetSpec>,
    #[serde(default)]
    custom: BTreeMap<String, Value>,
}

async fn append_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AppendRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let role = state.authorize(&headers, Action::Emit)?.role;
    let mut event = AuditEvent::new(req.actor_type, req.actor, req.method, req.url, req.content);
    if let Some(at) = req.occurred_at {
        event.occurred_at = at;
    }
    event.targets = req.targets;
    event.custom = req.custom;
    // enqueue only — 202: durability is the pipeline's job (retries + DLQ)
    state.handle.emit(&role, event)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "status": "queued" })),
    ))
}

async fn query_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<LogQuery>,
) -> Result<Json<Vec<quipu_core::LogView>>, ApiError> {
    let caller = state.authorize(&headers, Action::Query)?;
    // queries are full scans — hold one of the token's slots for the whole
    // scan so a single token cannot monopolise the blocking pool
    let _slot = match state.query_slot(&caller.token_hash) {
        QuerySlot::Busy => {
            return Err(ApiError {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "too many concurrent queries for this token".into(),
            })
        }
        slot => slot,
    };
    let role = caller.role;
    let handle = state.handle.clone();
    // the scan runs on the snapshot in the blocking pool; appends keep flowing
    Ok(Json(blocking(move || handle.query(&role, q)).await?))
}

// ---- registry browsing -------------------------------------------------------

#[derive(Deserialize)]
struct ListParams {
    #[serde(default)]
    include_deleted: bool,
}

async fn list_entities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(type_name): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<quipu_core::TargetSnapshot>>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let handle = state.handle.clone();
    Ok(Json(
        blocking(move || handle.list_entities(&role, type_name, params.include_deleted)).await?,
    ))
}

async fn entity_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((type_name, entity_id)): Path<(String, String)>,
) -> Result<Json<Vec<quipu_core::TargetSnapshot>>, ApiError> {
    let role = state.authorize(&headers, Action::Query)?.role;
    let handle = state.handle.clone();
    Ok(Json(
        blocking(move || handle.entity_history(&role, type_name, entity_id)).await?,
    ))
}

// ---- admin ---------------------------------------------------------------------

async fn admin_flush(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    state.authorize(&headers, Action::Administer)?;
    let handle = state.handle.clone();
    blocking(move || handle.flush()).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_redrive(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    let n = blocking(move || handle.redrive_dlq(&role)).await?;
    Ok(Json(serde_json::json!({ "redriven": n })))
}

async fn admin_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    let n = blocking(move || handle.apply_retention(&role)).await?;
    Ok(Json(serde_json::json!({ "segments_dropped": n })))
}

async fn admin_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    let n = blocking(move || handle.dlq_len(&role)).await?;
    Ok(Json(serde_json::json!({ "parked": n })))
}

/// Verify the store's tamper-evidence hash chains. A found chain break is a
/// *successful* verification: 200 with `"ok": false` and the problem listed —
/// only "could not verify at all" is an error status. At most one
/// verification runs at a time (shared with the periodic task); a second
/// request gets 409 and should retry later.
async fn admin_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<VerifyReport>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let Some(guard) = state.try_begin_verify() else {
        return Err(ApiError {
            status: StatusCode::CONFLICT,
            message: "an integrity verification is already running".into(),
        });
    };
    let handle = state.handle.clone();
    // full-store scan: run it in the blocking pool, holding the guard until
    // the scan finishes
    let report = blocking(move || {
        let _running = guard;
        handle.verify_integrity(&role)
    })
    .await?;
    state.verify_runs.fetch_add(1, Ordering::AcqRel);
    Ok(Json(report))
}

/// Background verification loop (config section `verify`): one pass at
/// startup, then one per `interval`. A pass that finds a chain break — or
/// cannot run — logs at `error`; that log line is the alerting hook. Skips a
/// tick (at `warn`) when a verification is already running.
pub fn spawn_periodic_verify(state: AppState, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // the pipeline behind AppState enforces nothing (the HTTP layer
        // does), so this internal identity is only a label in error messages
        let role = Role::new("periodic-verify");
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(guard) = state.try_begin_verify() else {
                tracing::warn!("periodic verify skipped: a verification is already running");
                continue;
            };
            let handle = state.handle.clone();
            let role = role.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _running = guard;
                handle.verify_integrity(&role)
            })
            .await;
            match result {
                Ok(Ok(report)) => {
                    state.verify_runs.fetch_add(1, Ordering::AcqRel);
                    if report.ok {
                        tracing::info!(
                            segments = report.segments_checked,
                            log_records = report.log_records,
                            "periodic integrity verification passed"
                        );
                    } else {
                        tracing::error!(
                            problems = ?report.problems,
                            segments = report.segments_checked,
                            "integrity verification FAILED — the store shows tampering or corruption"
                        );
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "periodic integrity verification could not run")
                }
                Err(e) => tracing::error!(error = %e, "periodic verify task panicked"),
            }
        }
    })
}
