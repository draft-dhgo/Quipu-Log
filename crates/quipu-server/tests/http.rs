use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use quipu_core::{AuditStore, KeyRing, StoreConfig, SyncPolicy};
use quipu_middleware::{Action, AuditPipeline, PermissionPolicy, PipelineConfig, Role};
use quipu_server::{router, AppState};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

fn test_app(root: &std::path::Path) -> (Router, AuditPipeline) {
    let keys = KeyRing::new().with_hmac_key(b"test-hmac-key");
    let store = AuditStore::open(
        StoreConfig::new(root)
            .keys(keys)
            .sync_policy(SyncPolicy::Always),
    )
    .unwrap();
    let policy = PermissionPolicy::deny_by_default()
        .grant(
            Role::new("admin"),
            &[Action::Emit, Action::Query, Action::Administer],
        )
        .grant(Role::new("writer"), &[Action::Emit])
        .grant(Role::new("reader"), &[Action::Query]);
    let pipeline = AuditPipeline::start(
        store,
        root.to_path_buf(),
        policy.clone(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let tokens: HashMap<String, String> = [
        ("admin-token", "admin"),
        ("writer-token", "writer"),
        ("reader-token", "reader"),
    ]
    .into_iter()
    .map(|(t, r)| (t.to_string(), r.to_string()))
    .collect();
    let state = AppState {
        handle: pipeline.handle(),
        tokens: Arc::new(tokens),
        policy: Arc::new(policy),
    };
    (router(state), pipeline)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

fn user_schema() -> Value {
    json!({
        "type_name": "user",
        "fields": [{
            "name": "name",
            "kind": "Text",
            "protection": "None",
            "indexed": true,
            "required": false,
            "search": "None"
        }]
    })
}

fn append_body(actor_name: &str, url: &str) -> Value {
    json!({
        "actor_type": "user",
        "actor": { "entity_id": actor_name, "fields": { "name": { "Text": actor_name } } },
        "method": "POST",
        "url": url,
        "content": { "Text": "did a thing" },
        "targets": [{
            "entity_type": "user",
            "input": { "entity_id": "bob", "fields": { "name": { "Text": "Bob" } } }
        }]
    })
}

#[tokio::test]
async fn full_append_query_flow() {
    let dir = tempfile::tempdir().unwrap();
    let (app, pipeline) = test_app(dir.path());

    // health needs no token
    let (status, _) = send(&app, "GET", "/v1/healthz", None, None).await;
    assert_eq!(status, StatusCode::OK);

    // schema definition is admin-only
    let (status, _) = send(
        &app,
        "POST",
        "/v1/types",
        Some("admin-token"),
        Some(user_schema()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // append as writer, then flush as admin so the queued event is durable
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs",
        Some("writer-token"),
        Some(append_body("alice", "/api/things")),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (status, _) = send(&app, "POST", "/v1/admin/flush", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // unfiltered query sees the log
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("reader-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hits = body.as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["url"], "/api/things");
    assert_eq!(hits[0]["actor"]["entity_id"], "alice");
    assert_eq!(hits[0]["targets"][0]["entity_id"], "bob");

    // filtered by target attribute
    let q = json!({ "targets": [{
        "entity_type": "user", "field": "name", "value": { "Text": "Bob" }
    }]});
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("reader-token"),
        Some(q),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);

    // a probe that matches nothing
    let q = json!({ "targets": [{
        "entity_type": "user", "field": "name", "value": { "Text": "Mallory" }
    }]});
    let (_, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("reader-token"),
        Some(q),
    )
    .await;
    assert_eq!(body.as_array().unwrap().len(), 0);

    // registry browsing
    let (status, body) = send(&app, "GET", "/v1/entities/user", Some("reader-token"), None).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["entity_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["alice", "bob"]);

    let (status, body) = send(
        &app,
        "GET",
        "/v1/entities/user/alice/history",
        Some("reader-token"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);

    // schema listing and DLQ status
    let (status, body) = send(&app, "GET", "/v1/types", Some("reader-token"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    let (status, body) = send(&app, "GET", "/v1/admin/dlq", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["parked"], 0);

    pipeline.shutdown();
}

#[tokio::test]
async fn auth_and_permission_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (app, pipeline) = test_app(dir.path());

    // no token / unknown token -> 401
    let (status, _) = send(&app, "POST", "/v1/logs/query", None, Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("nope"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // role lacking the action -> 403
    let (status, _) = send(
        &app,
        "POST",
        "/v1/types",
        Some("writer-token"),
        Some(user_schema()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("writer-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs",
        Some("reader-token"),
        Some(append_body("alice", "/x")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, "POST", "/v1/admin/flush", Some("reader-token"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // schema misuse -> 400 (querying a type that has no registry)
    let q = json!({ "targets": [{
        "entity_type": "ghost", "field": "name", "value": { "Text": "x" }
    }]});
    let (status, body) = send(&app, "POST", "/v1/logs/query", Some("admin-token"), Some(q)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // appending for an undefined type is accepted (202) but parks in the DLQ
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs",
        Some("admin-token"),
        Some(append_body("alice", "/x")),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = send(&app, "POST", "/v1/admin/flush", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = send(&app, "GET", "/v1/admin/dlq", Some("admin-token"), None).await;
    assert_eq!(body["parked"], 1);

    pipeline.shutdown();
}
