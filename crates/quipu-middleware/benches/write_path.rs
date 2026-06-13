//! Write-path benchmarks: emit throughput (enqueue -> durable on the writer
//! thread) and per-call emit latency percentiles.
//!
//! Run: `cargo bench -p quipu-middleware --bench write_path`
//!
//! The latency section prints p50/p99/p99.9 of the caller-side `emit()` call
//! (the cost the host application's request path actually pays — persistence
//! happens on the writer thread) plus the end-to-end durable throughput of
//! emit + flush.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use quipu_core::*;
use quipu_middleware::*;
use std::time::{Duration, Instant};

struct Bench {
    pipeline: AuditPipeline,
    handle: AuditHandle,
    _dir: tempfile::TempDir,
}

fn pipeline(sync: SyncPolicy, queue: usize) -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir.path()).sync_policy(sync);
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store.define_type(default_target_type()).unwrap();
    let pipeline = AuditPipeline::start(
        store,
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig {
            queue_capacity: queue,
            ..Default::default()
        },
        None,
    )
    .unwrap();
    let handle = pipeline.handle();
    Bench {
        pipeline,
        handle,
        _dir: dir,
    }
}

fn event(i: usize) -> AuditEvent {
    AuditEvent::new(
        "default_actor",
        EntityInput::new("svc-1").text("name", "bench"),
        "POST",
        format!("/api/bench/{i}"),
        Content::Text("bench payload".into()),
    )
    .target(TargetSpec::new(
        "default_target",
        EntityInput::new("t-1").text("name", "thing"),
    ))
}

/// Durable throughput: 1000 events enqueued, then flush() waits until every
/// one is on disk. Measures the full write path, not just the channel.
fn bench_emit_durable(c: &mut Criterion) {
    let mut g = c.benchmark_group("write_path");
    g.throughput(Throughput::Elements(1000));
    g.measurement_time(Duration::from_secs(15));
    for (name, sync) in [
        ("emit_1k_flush/os_managed", SyncPolicy::OsManaged),
        ("emit_1k_flush/fsync_every_64", SyncPolicy::EveryN(64)),
    ] {
        let b = pipeline(sync, 16384);
        g.bench_function(name, |bench| {
            bench.iter_batched(
                || (0..1000).map(event).collect::<Vec<_>>(),
                |events| {
                    for ev in events {
                        b.handle.emit_unchecked(ev).expect("emit failed");
                    }
                    b.handle.flush().expect("flush failed");
                },
                BatchSize::PerIteration,
            )
        });
        b.pipeline.shutdown();
    }
    g.finish();
}

/// Caller-side emit() latency: what an audited request pays inline. Reported
/// as explicit percentiles because tail latency is the number that matters.
fn report_emit_latency() {
    const N: usize = 200_000;
    let b = pipeline(SyncPolicy::EveryN(64), 32768);
    let mut lat = Vec::with_capacity(N);
    let start = Instant::now();
    for i in 0..N {
        let ev = event(i);
        let t = Instant::now();
        let mut ev = ev;
        loop {
            match b.handle.emit_unchecked(ev) {
                Ok(()) => break,
                Err(MiddlewareError::QueueFull(back)) => {
                    ev = *back;
                    std::thread::sleep(Duration::from_micros(50));
                }
                Err(e) => panic!("emit failed: {e}"),
            }
        }
        lat.push(t.elapsed());
    }
    b.handle.flush().expect("flush failed");
    let wall = start.elapsed();
    lat.sort_unstable();
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    println!("\n== emit() caller-side latency over {N} events (fsync every 64) ==");
    println!("p50  {:>10.2?}", pct(0.50));
    println!("p99  {:>10.2?}", pct(0.99));
    println!("p99.9{:>10.2?}", pct(0.999));
    println!("max  {:>10.2?}", lat[lat.len() - 1]);
    println!(
        "durable end-to-end: {N} events in {wall:.2?} = {:.0} events/s\n",
        N as f64 / wall.as_secs_f64()
    );
    b.pipeline.shutdown();
}

fn benches(c: &mut Criterion) {
    bench_emit_durable(c);
    report_emit_latency();
}

criterion_group!(write_path, benches);
criterion_main!(write_path);
