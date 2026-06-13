//! Crash injection: a child process writes through the full pipeline and the
//! parent SIGKILLs it at a random moment, over and over. After every kill the
//! store must (a) reopen — torn tails are recovered, not fatal — and (b) pass
//! full hash-chain verification, with the durable record count never going
//! backwards.
//!
//! Ignored by default. Run with:
//!
//! ```text
//! QUIPU_CRASH_ITERS=20 cargo test -p quipu-middleware --test crash -- --ignored --nocapture
//! ```
#![cfg(unix)]

use quipu_core::*;
use quipu_middleware::*;
use std::time::Duration;

const CHILD_ENV: &str = "QUIPU_CRASH_CHILD_DIR";

fn open_store(root: &std::path::Path) -> AuditStore {
    // EveryN(8): most appends are durable, so the surviving record count is
    // expected to actually grow between kills
    let cfg = StoreConfig::new(root)
        .max_segment_bytes(128 * 1024)
        .sync_policy(SyncPolicy::EveryN(8));
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

/// Child mode: emit events as fast as possible until killed. This "test" is
/// a no-op unless the parent set CHILD_ENV — the harness is just a convenient
/// way to get a second process running our code.
#[test]
#[ignore = "internal child process for crash_kill_recover_verify"]
fn crash_writer_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let root = std::path::PathBuf::from(dir);
    let pipeline = AuditPipeline::start(
        open_store(&root),
        root.clone(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            queue_capacity: 1024,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    let mut i = 0u64;
    loop {
        let ev = AuditEvent::new(
            "default_actor",
            EntityInput::new("svc-1").text("name", "crashy"),
            "POST",
            format!("/api/crash/{i}"),
            Content::Text("crash payload".into()),
        )
        .target(TargetSpec::new(
            "default_target",
            EntityInput::new("t-1").text("name", "thing"),
        ));
        match handle.emit_unchecked(ev) {
            Ok(()) => i += 1,
            Err(MiddlewareError::QueueFull(_)) => std::thread::sleep(Duration::from_micros(100)),
            Err(e) => panic!("emit failed: {e}"),
        }
    }
}

fn durable_log_count(root: &std::path::Path) -> usize {
    let mut store = open_store(root);
    store
        .query(&LogQuery::default())
        .expect("query after recovery failed")
        .len()
}

#[test]
#[ignore = "long-running; QUIPU_CRASH_ITERS controls iterations (default 5)"]
fn crash_kill_recover_verify() {
    let iters: u32 = std::env::var("QUIPU_CRASH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut last_count = 0usize;

    for iter in 0..iters {
        let mut child = std::process::Command::new(&exe)
            .args(["--exact", "crash_writer_child", "--ignored", "--nocapture"])
            .env(CHILD_ENV, dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn child writer");

        // let it write for a random-ish slice of time, then SIGKILL mid-write
        let ms = 80 + (quipu_core::time::now_micros() % 400);
        std::thread::sleep(Duration::from_millis(ms));
        child.kill().expect("kill failed"); // SIGKILL on unix
        child.wait().unwrap();

        // recovery: reopen must succeed and the whole chain must verify
        let mut store = open_store(dir.path());
        store
            .verify_integrity()
            .unwrap_or_else(|e| panic!("iteration {iter}: chain verification failed: {e}"));
        drop(store);

        let count = durable_log_count(dir.path());
        assert!(
            count >= last_count,
            "iteration {iter}: durable records went backwards ({last_count} -> {count})"
        );
        println!("iteration {iter}: killed after {ms}ms, {count} records verified");
        last_count = count;
    }
    assert!(last_count > 0, "no records survived any iteration");
}
