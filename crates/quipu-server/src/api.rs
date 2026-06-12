use crate::auth::role_for;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use quipu_core::{Content, CustomColumnDef, EntityInput, LogQuery, TypeSchema, Value};
use quipu_middleware::{
    Action, AuditEvent, AuditHandle, MiddlewareError, PermissionPolicy, Role, TargetSpec,
};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub handle: AuditHandle,
    /// Bearer token -> role name.
    pub tokens: Arc<HashMap<String, String>>,
    /// Same policy the pipeline enforces; the server consults it directly for
    /// endpoints whose handle methods are not permission-gated (flush).
    pub policy: Arc<PermissionPolicy>,
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
        .route("/v1/admin/flush", post(admin_flush))
        .route("/v1/admin/redrive", post(admin_redrive))
        .route("/v1/admin/retention", post(admin_retention))
        .route("/v1/admin/dlq", get(admin_dlq))
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

impl AppState {
    fn authenticate(&self, headers: &HeaderMap) -> Result<Role, ApiError> {
        role_for(headers, &self.tokens).ok_or_else(unauthorized)
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
    let role = state.authenticate(&headers)?;
    let handle = state.handle.clone();
    blocking(move || handle.define_type(&role, schema)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_types(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TypeSchema>>, ApiError> {
    let role = state.authenticate(&headers)?;
    let handle = state.handle.clone();
    Ok(Json(blocking(move || handle.entity_types(&role)).await?))
}

async fn define_column(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(def): Json<CustomColumnDef>,
) -> Result<StatusCode, ApiError> {
    let role = state.authenticate(&headers)?;
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
    let role = state.authenticate(&headers)?;
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
    let role = state.authenticate(&headers)?;
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
    let role = state.authenticate(&headers)?;
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
    let role = state.authenticate(&headers)?;
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
    let role = state.authenticate(&headers)?;
    // AuditHandle::flush is ungated (embedded hosts flush their own store);
    // over the network it is an admin lever, so gate it here
    if !state.policy.is_allowed(&role, Action::Administer) {
        return Err(MiddlewareError::PermissionDenied {
            role,
            action: Action::Administer,
        }
        .into());
    }
    let handle = state.handle.clone();
    blocking(move || handle.flush()).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_redrive(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authenticate(&headers)?;
    let handle = state.handle.clone();
    let n = blocking(move || handle.redrive_dlq(&role)).await?;
    Ok(Json(serde_json::json!({ "redriven": n })))
}

async fn admin_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authenticate(&headers)?;
    let handle = state.handle.clone();
    let n = blocking(move || handle.apply_retention(&role)).await?;
    Ok(Json(serde_json::json!({ "segments_dropped": n })))
}

async fn admin_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let role = state.authenticate(&headers)?;
    let handle = state.handle.clone();
    let n = blocking(move || handle.dlq_len(&role)).await?;
    Ok(Json(serde_json::json!({ "parked": n })))
}
