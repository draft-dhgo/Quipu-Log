use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use quipu_core::{AuditStore, KeyRing, StoreConfig, SyncPolicy};
use quipu_middleware::{
    Action, AuditPipeline, DiskThresholds, PermissionPolicy, PipelineConfig, Role,
};
use quipu_server::config::AuthSection;
use quipu_server::{router, AppState, AuthState};
use serde_json::{json, Value};
use tower::ServiceExt;

fn test_state(root: &std::path::Path, pipeline_cfg: PipelineConfig) -> (AppState, AuditPipeline) {
    let keys = KeyRing::new().with_hmac_key(b"test-hmac-key");
    let mut store = AuditStore::open(
        StoreConfig::new(root)
            .keys(keys)
            .sync_policy(SyncPolicy::Always),
    )
    .unwrap();
    store.define_type(quipu_core::default_actor_type()).unwrap();
    let policy = PermissionPolicy::deny_by_default().grant(
        Role::new("admin"),
        &[Action::Emit, Action::Query, Action::Administer],
    );
    let pipeline = AuditPipeline::start(
        store,
        root.to_path_buf(),
        PermissionPolicy::allow_all(),
        pipeline_cfg,
        None,
    )
    .unwrap();
    let auth: AuthSection = serde_json::from_value(json!({
        "tokens": { "admin-token": "admin" },
        "grants": { "admin": ["emit", "query", "administer"] }
    }))
    .unwrap();
    let state = AppState::new(
        pipeline.handle(),
        AuthState {
            tokens: auth.token_map().unwrap(),
            policy,
            max_concurrent_queries: None,
        },
        root.to_path_buf(),
    );
    (state, pipeline)
}

async fn get_raw(app: &Router, uri: &str, token: Option<&str>) -> (StatusCode, String) {
    let mut req = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn append_body() -> Value {
    json!({
        "actor_type": "default_actor",
        "actor": { "entity_id": "alice", "fields": { "name": { "Text": "alice" } } },
        "method": "POST",
        "url": "/api/things",
        "content": { "Text": "did a thing" }
    })
}

async fn emit_and_flush(app: &Router, n: usize) {
    for _ in 0..n {
        let req = Request::builder()
            .method("POST")
            .uri("/v1/logs")
            .header("authorization", "Bearer admin-token")
            .header("content-type", "application/json")
            .body(Body::from(append_body().to_string()))
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/flush")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
}

fn metric_value(body: &str, name: &str) -> f64 {
    body.lines()
        .find(|l| l.starts_with(name) && l[name.len()..].starts_with(' '))
        .unwrap_or_else(|| panic!("metric {name} missing in:\n{body}"))
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn metrics_require_admin_and_reflect_writes() {
    let dir = tempfile::tempdir().unwrap();
    let (state, pipeline) = test_state(dir.path(), PipelineConfig::default());
    let app = router(state);

    // admin-gated like the other operational endpoints
    let (status, _) = get_raw(&app, "/metrics", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = get_raw(&app, "/metrics", Some("admin-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metric_value(&body, "quipu_writes_ok_total"), 0.0);

    emit_and_flush(&app, 3).await;

    let (_, body) = get_raw(&app, "/metrics", Some("admin-token")).await;
    assert_eq!(metric_value(&body, "quipu_writes_ok_total"), 3.0);
    assert_eq!(
        metric_value(&body, "quipu_write_latency_seconds_count"),
        3.0
    );
    assert_eq!(metric_value(&body, "quipu_queue_depth"), 0.0);
    assert_eq!(metric_value(&body, "quipu_dlq_entries"), 0.0);
    assert_eq!(metric_value(&body, "quipu_writer_alive"), 1.0);
    assert!(metric_value(&body, "quipu_store_bytes") > 0.0);
    assert!(body.contains("quipu_write_latency_seconds_bucket{le=\"+Inf\"} 3"));

    pipeline.shutdown();
}

#[tokio::test]
async fn healthz_is_ok_then_unhealthy_when_writer_dies() {
    let dir = tempfile::tempdir().unwrap();
    let (state, pipeline) = test_state(dir.path(), PipelineConfig::default());
    let app = router(state);

    let (status, body) = get_raw(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "ok");
    assert!(v["reasons"].as_array().unwrap().is_empty());

    // stop the writer thread: persistence is gone, healthz must say so
    pipeline.shutdown();
    let (status, body) = get_raw(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "unhealthy");
    assert!(body.contains("writer thread"));
}

#[tokio::test]
async fn healthz_degrades_below_disk_thresholds() {
    let dir = tempfile::tempdir().unwrap();
    // impossible ratio: any real filesystem reads as low on space
    let cfg = PipelineConfig {
        disk_thresholds: DiskThresholds {
            min_free_bytes: 0,
            min_free_ratio: 1.1,
        },
        ..Default::default()
    };
    let (state, pipeline) = test_state(dir.path(), cfg);
    let app = router(state);

    let (status, body) = get_raw(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::OK, "degraded still answers 200");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "degraded");
    assert!(body.contains("free disk space low"));

    pipeline.shutdown();
}

#[tokio::test]
async fn healthz_unhealthy_while_disk_full_latch_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let (state, pipeline) = test_state(dir.path(), PipelineConfig::default());
    let handle = state.handle.clone();
    let app = router(state);

    handle.health_state().set_disk_full(true);
    let (status, body) = get_raw(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("disk is full"));

    // /metrics exposes the latch too
    let (_, metrics_body) = get_raw(&app, "/metrics", Some("admin-token")).await;
    assert_eq!(metric_value(&metrics_body, "quipu_disk_full"), 1.0);

    handle.health_state().set_disk_full(false);
    let (status, _) = get_raw(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::OK);

    pipeline.shutdown();
}

#[tokio::test]
async fn disk_full_fast_reject_answers_507() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = PipelineConfig {
        reject_emit_when_disk_full: true,
        ..Default::default()
    };
    let (state, pipeline) = test_state(dir.path(), cfg);
    let handle = state.handle.clone();
    let app = router(state);

    handle.health_state().set_disk_full(true);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/logs")
        .header("authorization", "Bearer admin-token")
        .header("content-type", "application/json")
        .body(Body::from(append_body().to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INSUFFICIENT_STORAGE);

    let (_, body) = get_raw(&app, "/metrics", Some("admin-token")).await;
    assert_eq!(
        metric_value(&body, "quipu_emit_rejected_total{reason=\"disk_full\"}"),
        1.0
    );

    pipeline.shutdown();
}
