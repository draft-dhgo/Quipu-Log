//! Meta-audit through the async pipeline: queries and admin operations leave
//! access records, reading the access log does not snowball, and probe
//! values stay out of the trail.

use quipu_core::*;
use quipu_middleware::*;
use std::collections::BTreeMap;

fn store_at(root: &std::path::Path) -> AuditStore {
    let cfg = StoreConfig::new(root)
        .sync_policy(SyncPolicy::OsManaged)
        .access_log(true);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn pipeline_at(root: &std::path::Path) -> AuditPipeline {
    AuditPipeline::start(
        store_at(root),
        root.to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap()
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
fn query_leaves_access_record_with_actor_operation_and_count() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = pipeline_at(dir.path());
    let handle = pipeline.handle();
    let auditor = Role::new("auditor");

    for i in 0..7 {
        handle.emit(&auditor, event(&format!("/api/{i}"))).unwrap();
    }
    handle.flush().unwrap();
    assert_eq!(handle.query(&auditor, LogQuery::default()).unwrap().len(), 7);

    let recs = handle
        .query_access(
            &auditor,
            AccessQuery {
                operation: Some("query_logs".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].actor, "auditor");
    assert_eq!(recs[0].operation, "query_logs");
    assert_eq!(recs[0].result_count, Some(7));
    pipeline.shutdown();
}

#[test]
fn reading_the_access_log_grows_it_by_exactly_one_record_per_read() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = pipeline_at(dir.path());
    let handle = pipeline.handle();
    let admin = Role::new("admin");

    // each query_access run records itself once (after computing its own
    // result, so a read never sees its own record) — strictly linear growth,
    // no self-reference blow-up
    let mut last = None;
    for i in 0..5u64 {
        let recs = handle.query_access(&admin, AccessQuery::default()).unwrap();
        assert_eq!(recs.len() as u64, i, "read #{i} saw {} records", recs.len());
        last = Some(recs);
    }
    let last = last.unwrap();
    assert!(last.iter().all(|r| r.operation == "query_access"));
    assert!(last.iter().all(|r| r.actor == "admin"));
    pipeline.shutdown();
}

#[test]
fn admin_operations_are_meta_audited() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = pipeline_at(dir.path());
    let handle = pipeline.handle();
    let admin = Role::new("admin");

    assert_eq!(handle.redrive_dlq(&admin).unwrap().replayed, 0);
    assert_eq!(handle.apply_retention(&admin).unwrap(), 0);
    assert_eq!(handle.dlq_len(&admin).unwrap(), 0);
    assert!(handle.verify_integrity(&admin).unwrap().ok);

    let op = |name: &str| AccessQuery {
        operation: Some(name.into()),
        ..Default::default()
    };
    for name in ["redrive_dlq", "apply_retention", "dlq_len", "verify"] {
        let recs = handle.query_access(&admin, op(name)).unwrap();
        assert_eq!(recs.len(), 1, "missing access record for {name}");
        assert_eq!(recs[0].actor, "admin");
    }
    pipeline.shutdown();
}

#[test]
fn probe_values_do_not_reach_the_access_log() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = pipeline_at(dir.path());
    let handle = pipeline.handle();
    let auditor = Role::new("auditor");

    handle.emit(&auditor, event("/api/x")).unwrap();
    handle.flush().unwrap();
    let q = LogQuery {
        targets: vec![TargetFilter::exact(
            "default_target",
            "name",
            Value::Text("SECRET-PROBE-42".into()),
        )],
        custom: BTreeMap::new(),
        ..Default::default()
    };
    handle.query(&auditor, q).unwrap();

    let recs = handle
        .query_access(
            &auditor,
            AccessQuery {
                operation: Some("query_logs".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(recs.len(), 1);
    assert!(
        !recs[0].params.contains("SECRET-PROBE-42"),
        "probe leaked: {}",
        recs[0].params
    );
    assert!(recs[0].params.contains("default_target"));
    pipeline.shutdown();
}

#[test]
fn access_log_respects_permissions_and_disabled_store() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::deny_by_default().grant(Role::new("reader"), &[Action::Query]),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    // reading the access log is Administer-only
    assert!(matches!(
        handle.query_access(&Role::new("reader"), AccessQuery::default()),
        Err(MiddlewareError::PermissionDenied { .. })
    ));
    pipeline.shutdown();

    // disabled access log: queries still work, reads of the log error
    let dir2 = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir2.path()).sync_policy(SyncPolicy::OsManaged);
    let pipeline = AuditPipeline::start(
        AuditStore::open(cfg).unwrap(),
        dir2.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    handle.query(&Role::new("any"), LogQuery::default()).unwrap();
    assert!(matches!(
        handle.query_access(&Role::new("any"), AccessQuery::default()),
        Err(MiddlewareError::Core(quipu_core::Error::Schema(_)))
    ));
    pipeline.shutdown();
}
