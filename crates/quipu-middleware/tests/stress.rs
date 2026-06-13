//! Concurrency stress: hammer one pipeline with parallel emitters while
//! flush, retention and queries run against it the whole time, then prove the
//! store's tamper-evidence chain still verifies.
//!
//! Ignored by default (long-running). Run with:
//!
//! ```text
//! QUIPU_STRESS_SECS=60 cargo test -p quipu-middleware --test stress -- --ignored --nocapture
//! ```

use quipu_core::*;
use quipu_middleware::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn env_secs(name: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default),
    )
}

fn event(thread: usize, i: usize) -> AuditEvent {
    AuditEvent::new(
        "default_actor",
        EntityInput::new(format!("svc-{thread}")).text("name", "stress"),
        "POST",
        format!("/api/stress/{thread}/{i}"),
        Content::Text("stress payload".into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new(format!("t-{thread}")).text("name", "thing"),
    ))
}

#[test]
#[ignore = "long-running; QUIPU_STRESS_SECS controls duration (default 15s)"]
fn emit_flush_retention_query_run_concurrently() {
    let duration = env_secs("QUIPU_STRESS_SECS", 15);
    let emitters: usize = std::env::var("QUIPU_STRESS_EMITTERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);

    let dir = tempfile::tempdir().unwrap();
    // small segments + a short retention window so segment rolls and
    // retention drops actually happen *during* the run
    let cfg = StoreConfig::new(dir.path())
        .max_segment_bytes(256 * 1024)
        .retention(RetentionPolicy::keep_for(Duration::from_secs(5)))
        .sync_policy(SyncPolicy::EveryN(256));
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store.define_type(default_target_type()).unwrap();

    let pipeline = AuditPipeline::start(
        store,
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            queue_capacity: 8192,
            // frequent housekeeping = periodic fsync + retention on top of
            // the explicit calls below
            housekeeping_interval: Duration::from_millis(200),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let emitted = Arc::new(AtomicUsize::new(0));
    let admin = Role::new("admin");
    let mut threads = Vec::new();

    // N emitters, full-throttle; QueueFull backs off and retries the same event
    for t in 0..emitters {
        let handle = pipeline.handle();
        let stop = stop.clone();
        let emitted = emitted.clone();
        threads.push(std::thread::spawn(move || {
            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let mut ev = event(t, i);
                loop {
                    match handle.emit_unchecked(ev) {
                        Ok(()) => break,
                        Err(MiddlewareError::QueueFull(back)) => {
                            ev = *back;
                            std::thread::sleep(Duration::from_micros(200));
                            if stop.load(Ordering::Relaxed) {
                                return;
                            }
                        }
                        Err(e) => panic!("emit failed: {e}"),
                    }
                }
                emitted.fetch_add(1, Ordering::Relaxed);
                i += 1;
            }
        }));
    }
    // flusher
    {
        let handle = pipeline.handle();
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                handle.flush().expect("flush failed");
                std::thread::sleep(Duration::from_millis(20));
            }
        }));
    }
    // retention enforcer
    {
        let handle = pipeline.handle();
        let stop = stop.clone();
        let admin = admin.clone();
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                handle.apply_retention(&admin).expect("retention failed");
                std::thread::sleep(Duration::from_millis(100));
            }
        }));
    }
    // querier: snapshot scans run on this thread while writes continue
    {
        let handle = pipeline.handle();
        let stop = stop.clone();
        let admin = admin.clone();
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                handle
                    .query(&admin, LogQuery::default())
                    .expect("query failed");
                std::thread::sleep(Duration::from_millis(50));
            }
        }));
    }

    std::thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().expect("worker thread panicked");
    }

    let handle = pipeline.handle();
    handle.flush().unwrap();
    let report = handle.verify_integrity(&admin).unwrap();
    assert!(
        report.ok,
        "integrity verification failed after stress: {:?}",
        report.problems
    );
    let n = emitted.load(Ordering::Relaxed);
    assert!(n > 0, "no events were emitted");
    println!(
        "stress: {n} events over {duration:?} with {emitters} emitters; \
         {} segments verified, {} log records on disk",
        report.segments_checked, report.log_records
    );
    pipeline.shutdown();

    // reopen after shutdown: recovery + chain verification must still hold
    let mut store =
        AuditStore::open(StoreConfig::new(dir.path()).sync_policy(SyncPolicy::OsManaged)).unwrap();
    store
        .verify_integrity()
        .expect("reopened store fails verification");
}
