use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use quipu_core::{AuditStore, KeyRing, StoreConfig, SyncPolicy};
use quipu_middleware::{Action, AuditPipeline, PermissionPolicy, PipelineConfig, Role};
use quipu_server::config::AuthSection;
use quipu_server::{router, sha256_hex, AppState, AuthState, QuerySlot};
use serde_json::{json, Value};
use tower::ServiceExt;

fn default_tokens() -> Value {
    json!({
        "admin-token": "admin",
        "writer-token": "writer",
        "reader-token": "reader"
    })
}

/// Pipeline runs `allow_all` and the AppState policy enforces, mirroring
/// main.rs (the policy must live HTTP-side to be hot-reloadable).
fn test_state(
    root: &std::path::Path,
    tokens: Value,
    max_concurrent_queries: Option<u32>,
) -> (AppState, AuditPipeline) {
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
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let auth: AuthSection = serde_json::from_value(json!({
        "tokens": tokens,
        "grants": {
            "admin": ["emit", "query", "administer"],
            "writer": ["emit"],
            "reader": ["query"]
        },
        "max_concurrent_queries": max_concurrent_queries
    }))
    .unwrap();
    let state = AppState::new(
        pipeline.handle(),
        AuthState {
            tokens: auth.token_map().unwrap(),
            policy,
            max_concurrent_queries,
        },
        root.to_path_buf(),
    );
    (state, pipeline)
}

fn test_app(root: &std::path::Path) -> (Router, AuditPipeline) {
    let (state, pipeline) = test_state(root, default_tokens(), None);
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

#[tokio::test]
async fn hashed_token_auth() {
    let dir = tempfile::tempdir().unwrap();
    let raw = "hush-token";
    let mut tokens = serde_json::Map::new();
    tokens.insert(format!("sha256:{}", sha256_hex(raw)), json!("reader"));
    let (state, pipeline) = test_state(dir.path(), Value::Object(tokens), None);
    let app = router(state);

    // the raw token authenticates against its stored hash
    let (status, body) = send(&app, "POST", "/v1/logs/query", Some(raw), Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // the hash itself is not a credential
    let hash = sha256_hex(raw);
    let (status, _) = send(&app, "POST", "/v1/logs/query", Some(&hash), Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    pipeline.shutdown();
}

#[tokio::test]
async fn expired_token_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tokens = json!({
        "stale-token": { "role": "reader", "expires": 1 },
        "fresh-token": { "role": "reader", "expires": now + 3600 }
    });
    let (state, pipeline) = test_state(dir.path(), tokens, None);
    let app = router(state);

    // expired token behaves exactly like an unknown one
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("stale-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("fresh-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    pipeline.shutdown();
}

#[tokio::test]
async fn concurrent_query_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, pipeline) = test_state(dir.path(), default_tokens(), Some(1));
    let app = router(state.clone());

    // occupy reader's only slot, as an in-flight query would
    let held = state.query_slot(&sha256_hex("reader-token"));
    assert!(matches!(held, QuerySlot::Acquired(_)));

    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("reader-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // the cap is per token: another token still gets through
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("admin-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // releasing the slot frees the budget
    drop(held);
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("reader-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    pipeline.shutdown();
}

#[tokio::test]
async fn verify_endpoint_reports_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let (state, pipeline) = test_state(dir.path(), default_tokens(), None);
    let app = router(state.clone());

    // seed one durable log so verification has chains to walk
    let (status, _) = send(
        &app,
        "POST",
        "/v1/types",
        Some("admin-token"),
        Some(user_schema()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs",
        Some("writer-token"),
        Some(append_body("alice", "/api/things")),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (status, _) = send(&app, "POST", "/v1/admin/flush", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // verify is administer-gated
    let (status, _) = send(&app, "POST", "/v1/admin/verify", Some("reader-token"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, "POST", "/v1/admin/verify", Some("writer-token"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // a clean store verifies green
    let (status, body) = send(&app, "POST", "/v1/admin/verify", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    assert!(body["segments_checked"].as_u64().unwrap() > 0, "{body}");
    assert_eq!(body["log_records"], 1, "{body}");
    assert_eq!(body["problems"].as_array().unwrap().len(), 0);

    // while a verification holds the slot, a second one is refused
    let held = state.try_begin_verify().expect("slot should be free");
    let (status, _) = send(&app, "POST", "/v1/admin/verify", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    drop(held);
    let (status, _) = send(&app, "POST", "/v1/admin/verify", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::OK);

    // flip one payload byte in a logs segment: tampering must be reported,
    // as a 200 with ok:false (the verification itself succeeded)
    let logs_dir = dir.path().join("logs");
    let seg = std::fs::read_dir(&logs_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .expect("a logs segment exists");
    let mut bytes = std::fs::read(&seg).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&seg, bytes).unwrap();

    let (status, body) = send(&app, "POST", "/v1/admin/verify", Some("admin-token"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], false, "{body}");
    assert!(!body["problems"].as_array().unwrap().is_empty(), "{body}");

    pipeline.shutdown();
}

#[tokio::test]
async fn periodic_verify_runs_on_interval() {
    let dir = tempfile::tempdir().unwrap();
    let (state, pipeline) = test_state(dir.path(), default_tokens(), None);

    let task =
        quipu_server::spawn_periodic_verify(state.clone(), std::time::Duration::from_millis(5));

    // one pass fires at startup, the next proves the loop ticks
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while state.verify_runs() < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "periodic verify never completed two passes"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    task.abort();
    pipeline.shutdown();
}

#[tokio::test]
async fn auth_reload_swaps_tokens_and_survives_bad_config() {
    let dir = tempfile::tempdir().unwrap();
    let store_root = dir.path().join("store");
    std::fs::create_dir_all(&store_root).unwrap();
    let (state, pipeline) = test_state(&store_root, default_tokens(), None);
    let app = router(state.clone());

    let cfg_path = dir.path().join("config.json");
    std::fs::write(
        &cfg_path,
        json!({
            "listen": "127.0.0.1:0",
            "store": { "root": dir.path().join("store") },
            "auth": {
                "tokens": { "rotated-token": "reader" },
                "grants": { "reader": ["query"] }
            }
        })
        .to_string(),
    )
    .unwrap();
    state.reload_auth(&cfg_path).unwrap();

    // revoked token is out, rotated one is in
    let (status, _) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("reader-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("rotated-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // a broken config file must not change anything
    std::fs::write(&cfg_path, "{ not json").unwrap();
    assert!(state.reload_auth(&cfg_path).is_err());
    let (status, body) = send(
        &app,
        "POST",
        "/v1/logs/query",
        Some("rotated-token"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    pipeline.shutdown();
}
