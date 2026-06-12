//! End-to-end demo: an axum API wrapped by the audit proxy.
//!
//! ```sh
//! cargo run -p axum-demo
//! # in another shell:
//! curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d 'hello world'
//! curl 'localhost:3000/audit/logs?name=doc-42'
//! ```

use audit_core::*;
use audit_middleware::*;
use axum::extract::{Query, State};
use axum::http::Method;
use axum::routing::{get, put};
use axum::{Json, Router};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let root = std::env::temp_dir().join("audit-logger-demo");
    let cfg = StoreConfig::new(&root)
        .retention(RetentionPolicy::days(90))
        .sync_policy(SyncPolicy::EveryN(32));
    let mut store = AuditStore::open(cfg).expect("open store");
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }

    let pipeline = AuditPipeline::start(
        store,
        root.clone(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        Some(Arc::new(|event, err| {
            eprintln!(
                "AUDIT FALLBACK: {} {} failed: {err}",
                event.method, event.url
            );
        })),
    )
    .expect("start pipeline");
    let handle = pipeline.handle();

    let audit_layer = AuditLayer::new(handle.clone())
        .rules(vec![EndpointRule::prefix("/api/")
            .method(Method::PUT)
            .capture_request()
            .capture_response()])
        .filters(FilterSet::new().pre(|req| {
            if req.uri.path() == "/api/health" {
                FilterDecision::Skip
            } else {
                FilterDecision::Audit
            }
        }))
        .target_extractor(|req, _res, _req_body, _res_body| {
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

    let app = Router::new()
        .route(
            "/api/docs/{id}",
            put(|body: String| async move { format!("saved: {body}") }),
        )
        .route("/api/health", get(|| async { "ok" }))
        .layer(audit_layer)
        // query endpoint lives outside the audited surface
        .route("/audit/logs", get(query_logs))
        .with_state(handle);

    println!(
        "demo listening on http://localhost:3000 (data in {})",
        root.display()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn query_logs(
    State(handle): State<AuditHandle>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let q = LogQuery {
        targets: params
            .get("name")
            .map(|name| TargetFilter::exact("default_target", "name", Value::Text(name.clone())))
            .into_iter()
            .collect(),
        limit: Some(100),
        ..Default::default()
    };
    let role = Role::new("demo");
    let views = tokio::task::spawn_blocking(move || handle.query(&role, q))
        .await
        .unwrap()
        .unwrap_or_default();
    Json(serde_json::to_value(views).unwrap())
}
