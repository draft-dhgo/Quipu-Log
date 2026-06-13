use crate::auth::{role_for, AuthState};
use crate::config::ServerConfig;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use quipu_core::{Content, CustomColumnDef, EntityInput, LogQuery, TypeSchema, Value};
use quipu_middleware::{
    AccessQuery, AccessRecord, Action, AuditEvent, AuditHandle, MiddlewareError, Role, TargetSpec,
    VerifyReport,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct AppState {
    pub handle: AuditHandle,
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
    pub fn new(handle: AuditHandle, auth: AuthState) -> Self {
        Self {
            handle,
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
        // token issue/revoke is admin activity worth a meta-audit record too
        // (no bearer token behind a SIGHUP — the actor is the host system)
        self.handle.record_access(AccessRecord::new(
            "system",
            "auth_reload",
            serde_json::json!({ "tokens_added": added, "tokens_removed": removed }).to_string(),
            None,
        ));
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
        .route("/v1/types", post(define_type).get(list_types))
        .route("/v1/columns", post(define_column))
        .route("/v1/logs", post(append_log))
        .route("/v1/logs/query", post(query_logs))
        .route("/v1/entities/{type_name}", get(list_entities))
        .route(
            "/v1/entities/{type_name}/{entity_id}/history",
            get(entity_history),
        )
        .route("/v1/access/query", post(query_access))
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

async fn healthz() -> &'static str {
    "ok"
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

// ---- meta-audit (access log) ---------------------------------------------------

/// Read the meta-audit access log: who queried/administered the audit store,
/// when, with what parameter shapes and result counts. Requires the
/// `administer` grant (access records reveal who searched what). Only
/// available when `store.access_log` is enabled in the config (400
/// otherwise). This read is itself recorded — one `query_access` record per
/// call, never more (the recording is an append, not a query).
async fn query_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(q): Json<AccessQuery>,
) -> Result<Json<Vec<AccessRecord>>, ApiError> {
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    Ok(Json(blocking(move || handle.query_access(&role, q)).await?))
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
    let role = state.authorize(&headers, Action::Administer)?.role;
    let handle = state.handle.clone();
    blocking(move || handle.flush()).await?;
    // flush() takes no role (it is also the pipeline's internal barrier), so
    // the HTTP layer records the admin action itself
    state
        .handle
        .record_access(AccessRecord::new(&role.0, "flush", "{}", None));
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
