use audit_core::*;
use audit_middleware::*;
use axum::routing::{get, put};
use axum::Router;
use http::Method;
use tower::ServiceExt;

fn store_at(root: &std::path::Path) -> AuditStore {
    let cfg = StoreConfig::new(root).sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn app(handle: AuditHandle) -> Router {
    let layer = AuditLayer::new(handle)
        .rules(vec![
            EndpointRule::prefix("/api/docs")
                .method(Method::PUT)
                .capture_request()
                .capture_response(),
            EndpointRule::prefix("/api/"),
        ])
        .filters(
            FilterSet::new()
                // pre-filter: never audit health checks
                .pre(|req| {
                    if req.uri.path() == "/api/health" {
                        FilterDecision::Skip
                    } else {
                        FilterDecision::Audit
                    }
                })
                // post-filter: skip cache hits, tag server errors
                .post(|_req, res, event| {
                    if res.status == http::StatusCode::NOT_MODIFIED {
                        return FilterDecision::Skip;
                    }
                    if res.status.is_server_error() {
                        event
                            .custom
                            .insert("severity".to_string(), Value::Text("error".into()));
                    }
                    FilterDecision::Audit
                }),
        )
        .target_extractor(|req, _res, _req_body, _res_body| {
            // derive the doc id straight from the url
            req.uri
                .path()
                .strip_prefix("/api/docs/")
                .map(|id| {
                    vec![TargetSpec::new(
                        "default_target",
                        EntityInput::new(id).text("name", format!("doc-{id}")),
                    )]
                })
                .unwrap_or_default()
        });

    Router::new()
        .route(
            "/api/docs/{id}",
            put(|body: String| async move { format!("saved:{body}") }),
        )
        .route("/api/health", get(|| async { "ok" }))
        .route("/outside", get(|| async { "not audited" }))
        .layer(layer)
}

async fn send(app: &Router, method: Method, uri: &str, body: &str) -> (http::StatusCode, String) {
    let req = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("x-audit-actor", "alice")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn proxies_and_audits_matching_endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = store_at(dir.path());
    store
        .define_custom_column(CustomColumnDef::new("severity", ValueKind::Text))
        .unwrap();
    let pipeline = AuditPipeline::start(
        store,
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    let app = app(handle.clone());

    // audited with body capture; the response must pass through intact
    let (status, body) = send(&app, Method::PUT, "/api/docs/42", "hello").await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(body, "saved:hello");

    // pre-filter exempts health checks; unmatched paths are not audited
    send(&app, Method::GET, "/api/health", "").await;
    let (status, body) = send(&app, Method::GET, "/outside", "").await;
    assert_eq!(
        (status, body.as_str()),
        (http::StatusCode::OK, "not audited")
    );

    handle.flush().unwrap();
    let role = Role::new("any");
    let hits = handle.query(&role, LogQuery::default()).unwrap();
    assert_eq!(hits.len(), 1, "only the PUT should be audited");

    let hit = &hits[0];
    assert_eq!(hit.method, "PUT");
    assert_eq!(hit.url, "/api/docs/42");
    assert_eq!(hit.actor.entity_id, "alice");
    assert_eq!(hit.targets.len(), 1);
    assert_eq!(hit.targets[0].entity_id, "42");
    let Content::Json(content) = &hit.content else {
        panic!("expected json content")
    };
    assert_eq!(content["request"], "hello");
    assert_eq!(content["response"], "saved:hello");
    assert_eq!(content["status"], 200);

    // target search finds the log by derived entity name
    let hits = handle
        .query(
            &role,
            LogQuery {
                targets: vec![TargetFilter::exact(
                    "default_target",
                    "name",
                    Value::Text("doc-42".into()),
                )],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(hits.len(), 1);

    pipeline.shutdown();
}

#[tokio::test]
async fn oversized_bodies_proxy_through_but_are_not_captured() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();

    let layer = AuditLayer::new(handle.clone()).rules(vec![EndpointRule::prefix("/api/")
        .capture_request()
        .capture_response()
        .capture_limit(16)]);
    let app = Router::new()
        .route(
            "/api/docs/{id}",
            put(|body: String| async move { format!("saved:{body}") }),
        )
        .layer(layer);

    let big = "x".repeat(64);
    let (status, body) = send(&app, Method::PUT, "/api/docs/1", &big).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(
        body,
        format!("saved:{big}"),
        "oversized body must proxy through intact"
    );

    handle.flush().unwrap();
    let hits = handle
        .query(&Role::new("any"), LogQuery::default())
        .unwrap();
    assert_eq!(hits.len(), 1);
    let Content::Json(content) = &hits[0].content else {
        panic!("expected json content")
    };
    let req = content["request"].as_str().unwrap();
    assert!(req.contains("exceeds the capture limit"), "got: {req}");
    let res = content["response"].as_str().unwrap();
    assert!(res.contains("exceeds the capture limit"), "got: {res}");

    pipeline.shutdown();
}

#[tokio::test]
async fn rule_level_target_extractor_wins_over_layer_wide() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();

    let layer = AuditLayer::new(handle.clone())
        .rules(vec![
            EndpointRule::prefix("/api/docs").target_extractor(|req, _res, _rb, _sb| {
                req.uri
                    .path()
                    .strip_prefix("/api/docs/")
                    .map(|id| {
                        vec![TargetSpec::new(
                            "default_target",
                            EntityInput::new(id).text("name", format!("rule-doc-{id}")),
                        )]
                    })
                    .unwrap_or_default()
            }),
            EndpointRule::prefix("/api/"),
        ])
        // layer-wide extractor: used by rules without their own
        .target_extractor(|_req, _res, _rb, _sb| {
            vec![TargetSpec::new(
                "default_target",
                EntityInput::new("generic").text("name", "generic"),
            )]
        });
    let app = Router::new()
        .route("/api/docs/{id}", put(|| async { "ok" }))
        .route("/api/other", put(|| async { "ok" }))
        .layer(layer);

    send(&app, Method::PUT, "/api/docs/7", "").await;
    send(&app, Method::PUT, "/api/other", "").await;
    handle.flush().unwrap();

    let role = Role::new("any");
    let by_name = |name: &str| LogQuery {
        targets: vec![TargetFilter::exact(
            "default_target",
            "name",
            Value::Text(name.into()),
        )],
        ..Default::default()
    };
    assert_eq!(handle.query(&role, by_name("rule-doc-7")).unwrap().len(), 1);
    assert_eq!(handle.query(&role, by_name("generic")).unwrap().len(), 1);

    pipeline.shutdown();
}
