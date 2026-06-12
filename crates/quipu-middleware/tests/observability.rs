use quipu_core::*;
use quipu_middleware::*;

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
}

fn bad_event() -> AuditEvent {
    // target type has no registry table -> every write attempt fails
    event("/api/broken").target(TargetSpec::new("ghost_type", EntityInput::new("g-1")))
}

#[test]
fn metrics_reflect_writes_after_emit_and_flush() {
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

    let before = handle.metrics();
    assert_eq!(before.writes_ok, 0);

    for i in 0..25 {
        handle
            .emit_unchecked(event(&format!("/api/m/{i}")))
            .unwrap();
    }
    handle.flush().unwrap();

    let m = handle.metrics();
    assert_eq!(m.writes_ok, 25);
    assert_eq!(m.queue_depth, 0, "flush drained the queue");
    assert_eq!(m.write_latency.count, 25);
    assert!(m.write_latency.sum_seconds > 0.0);
    // +Inf-equivalent: the widest bucket saw every write
    assert_eq!(m.write_latency.buckets.last().unwrap().1, 25);
    assert_eq!(m.dlq_entries, 0);
    assert_eq!(m.writes_parked, 0);
    assert_eq!(m.events_lost, 0);

    let h = handle.health();
    assert!(h.writer_alive);
    assert!(!h.disk_full);

    pipeline.shutdown();
}

#[test]
fn parked_events_show_in_metrics_and_gauge_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            max_retries: 1,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    handle.emit_unchecked(bad_event()).unwrap();
    handle.flush().unwrap();

    let m = handle.metrics();
    assert_eq!(m.writes_parked, 1);
    assert_eq!(m.dlq_entries, 1);
    assert_eq!(m.write_retries, 1, "one retry before parking");
    assert_eq!(m.writes_ok, 0);
    pipeline.shutdown();

    // a fresh pipeline seeds the DLQ gauge from disk
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    )
    .unwrap();
    assert_eq!(pipeline.handle().metrics().dlq_entries, 1);
    pipeline.shutdown();
}

#[test]
fn disk_full_latch_rejects_emits_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            reject_emit_when_disk_full: true,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();

    // simulate the writer having hit ENOSPC
    handle.health_state().set_disk_full(true);
    let err = handle.emit_unchecked(event("/api/x")).unwrap_err();
    assert!(matches!(err, MiddlewareError::DiskFull(ev) if ev.url == "/api/x"));
    assert_eq!(handle.metrics().emit_rejected_disk_full, 1);
    assert!(handle.health().disk_full);

    // space freed: latch released, emits flow again — and the first
    // successful write would also have cleared it
    handle.health_state().set_disk_full(false);
    handle.emit_unchecked(event("/api/y")).unwrap();
    handle.flush().unwrap();
    assert_eq!(handle.metrics().writes_ok, 1);
    assert!(!handle.health().disk_full);

    pipeline.shutdown();
}

#[test]
fn without_fast_reject_disk_full_latch_does_not_block_emits() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(), // reject_emit_when_disk_full: false
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    handle.health_state().set_disk_full(true);
    handle.emit_unchecked(event("/api/x")).unwrap();
    handle.flush().unwrap();
    // the write succeeded (disk is not actually full), which released the latch
    assert!(!handle.health().disk_full);
    pipeline.shutdown();
}

#[test]
fn writer_death_is_visible_in_health() {
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
    assert!(handle.health().writer_alive);
    pipeline.shutdown();
    assert!(
        !handle.health().writer_alive,
        "stopped writer must read as dead"
    );
    // metrics snapshots must keep working with a dead writer
    let _ = handle.metrics();
}

#[test]
fn queue_full_rejections_are_counted() {
    let dir = tempfile::tempdir().unwrap();
    let pipeline = AuditPipeline::start(
        store_at(dir.path()),
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            queue_capacity: 1,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    // hammer a capacity-1 queue until at least one emit bounces
    let mut bounced = 0;
    for i in 0..200 {
        if let Err(MiddlewareError::QueueFull(_)) =
            handle.emit_unchecked(event(&format!("/api/q/{i}")))
        {
            bounced += 1;
        }
    }
    if bounced > 0 {
        assert_eq!(handle.metrics().emit_rejected_queue_full, bounced);
    }
    handle.flush().unwrap();
    assert_eq!(handle.metrics().queue_depth, 0);
    pipeline.shutdown();
}
