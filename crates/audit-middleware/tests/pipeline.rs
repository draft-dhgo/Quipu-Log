use audit_core::*;
use audit_middleware::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn store_at(root: &std::path::Path) -> AuditStore {
    let cfg = StoreConfig::new(root).sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn event(url: &str) -> AuditEvent {
    AuditEvent::new(
        "default_actor",
        EntityInput::new("svc-1").text("name", "svc"),
        "POST",
        url,
        Content::Text("payload".into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new("t-1").text("name", "thing"),
    ))
}

#[test]
fn emits_asynchronously_and_queries_back() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::deny_by_default()
            .grant(Role::new("svc"), &[Action::Emit])
            .grant(Role::new("auditor"), &[Action::Query]),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    let svc = Role::new("svc");
    let auditor = Role::new("auditor");

    for i in 0..100 {
        handle
            .emit(&svc, event(&format!("/api/items/{i}")))
            .unwrap();
    }
    handle.flush().unwrap();

    let hits = handle.query(&auditor, LogQuery::default()).unwrap();
    assert_eq!(hits.len(), 100);

    // permission boundaries
    assert!(matches!(
        handle.emit(&auditor, event("/x")),
        Err(MiddlewareError::PermissionDenied { .. })
    ));
    assert!(matches!(
        handle.query(&svc, LogQuery::default()),
        Err(MiddlewareError::PermissionDenied { .. })
    ));
    assert!(matches!(
        handle.redrive_dlq(&svc),
        Err(MiddlewareError::PermissionDenied { .. })
    ));

    pipeline.shutdown();
}

#[test]
fn failed_events_park_in_dlq_then_redrive() {
    let dir = tempfile::tempdir().unwrap();
    let fallback_hits = Arc::new(AtomicUsize::new(0));
    let fb = fallback_hits.clone();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            max_retries: 0,
            ..Default::default()
        },
        Some(Arc::new(move |_event, _err| {
            fb.fetch_add(1, Ordering::SeqCst);
        })),
    )
    .unwrap();
    let handle = pipeline.handle();
    let admin = Role::new("admin");

    // an event whose target type has no registry table -> the write fails
    let bad = AuditEvent::new(
        "default_actor",
        EntityInput::new("svc-1").text("name", "svc"),
        "PUT",
        "/api/broken",
        Content::Text("x".into()),
    )
    .target(TargetSpec::new("ghost_type", EntityInput::new("g-1")));
    handle.emit(&admin, bad).unwrap();
    handle.flush().unwrap();

    assert_eq!(handle.dlq_len(&admin).unwrap(), 1);
    assert_eq!(fallback_hits.load(Ordering::SeqCst), 1);
    assert!(handle
        .query(&admin, LogQuery::default())
        .unwrap()
        .is_empty());

    // redrive still fails (type still missing) -> parked again
    assert_eq!(handle.redrive_dlq(&admin).unwrap(), 0);
    assert_eq!(handle.dlq_len(&admin).unwrap(), 1);
    pipeline.shutdown();

    // fix the schema, restart the pipeline, redrive succeeds
    let mut store = store_at(dir.path());
    store
        .define_type(TypeSchema::new("ghost_type", vec![FieldDef::text("name")]))
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
    assert_eq!(handle.dlq_len(&admin).unwrap(), 1, "dlq survives restart");
    assert_eq!(handle.redrive_dlq(&admin).unwrap(), 1);
    assert_eq!(handle.dlq_len(&admin).unwrap(), 0);
    let hits = handle.query(&admin, LogQuery::default()).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].url, "/api/broken");
    pipeline.shutdown();
}

#[test]
fn registry_browsing_through_the_handle() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::deny_by_default().grant(Role::new("auditor"), &[Action::Query]),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    let auditor = Role::new("auditor");

    handle.emit_unchecked(event("/api/items/1")).unwrap();
    handle.flush().unwrap();

    let types = handle.entity_types(&auditor).unwrap();
    assert!(types.iter().any(|t| t.type_name == "default_target"));

    let entities = handle
        .list_entities(&auditor, "default_target", false)
        .unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].entity_id, "t-1");

    let history = handle
        .entity_history(&auditor, "default_target", "t-1")
        .unwrap();
    assert_eq!(history.len(), 1);

    // registry browsing is permission-gated like queries
    assert!(matches!(
        handle.entity_types(&Role::new("nobody")),
        Err(MiddlewareError::PermissionDenied { .. })
    ));

    pipeline.shutdown();
}

#[test]
fn interrupted_redrive_swap_is_recovered_on_start() {
    let dir = tempfile::tempdir().unwrap();

    // park one event in the DLQ (target type has no registry)
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            max_retries: 0,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    let admin = Role::new("admin");
    let bad = AuditEvent::new(
        "default_actor",
        EntityInput::new("svc-1").text("name", "svc"),
        "PUT",
        "/api/broken",
        Content::Text("x".into()),
    )
    .target(TargetSpec::new("ghost_type", EntityInput::new("g-1")));
    handle.emit(&admin, bad).unwrap();
    handle.flush().unwrap();
    assert_eq!(handle.dlq_len(&admin).unwrap(), 1);
    pipeline.shutdown();

    // simulate a crash mid-swap: the rebuilt DLQ was renamed to staging and
    // the old directory was already removed
    let dlq = dir.path().join("dlq");
    let staging = dir.path().join("dlq.redrive");
    std::fs::rename(&dlq, &staging).unwrap();
    assert!(!dlq.exists());

    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    assert_eq!(
        handle.dlq_len(&admin).unwrap(),
        1,
        "staging dir adopted as the DLQ"
    );
    assert!(!staging.exists());
    pipeline.shutdown();
}

#[test]
fn throughput_smoke() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            queue_capacity: 20_000,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    let role = Role::new("svc");

    let n = 10_000;
    let start = std::time::Instant::now();
    for i in 0..n {
        handle
            .emit(&role, event(&format!("/api/perf/{i}")))
            .unwrap();
    }
    handle.flush().unwrap();
    let elapsed = start.elapsed();
    let per_sec = n as f64 / elapsed.as_secs_f64();
    println!("wrote {n} events in {elapsed:?} ({per_sec:.0}/s)");

    let hits = handle.query(&role, LogQuery::default()).unwrap();
    assert_eq!(hits.len(), n);
    pipeline.shutdown();
}
