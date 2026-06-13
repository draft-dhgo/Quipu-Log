//! Large-scale regression bench for time-range pruning and ordered
//! pagination. Ignored by default (it writes millions of rows); run with
//!
//! ```sh
//! QUIPU_BENCH_N=5000000 cargo test -p quipu-core --test scale --release -- --ignored --nocapture
//! ```
//!
//! What it demonstrates: with per-segment time bounds, a narrow time-range
//! query opens only the overlapping segment(s) instead of reading the whole
//! history, and a newest-first `limit` page stops after the newest segment.

use quipu_core::*;
use std::collections::BTreeMap;
use std::time::Instant;

fn bench_n() -> u64 {
    std::env::var("QUIPU_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000)
}

#[test]
#[ignore = "writes millions of rows; run explicitly with --ignored --nocapture (release!)"]
fn narrow_window_query_skips_cold_segments() {
    let n = bench_n();
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig::new(dir.path())
        .sync_policy(SyncPolicy::OsManaged)
        .max_segment_bytes(8 * 1024 * 1024);
    let mut store = AuditStore::open(cfg).unwrap();

    // bypass the registries (actor resolves as a `missing` snapshot): the
    // bench isolates the log-scan path, which is what pruning changes
    let actor = Uid::generate();
    let t_write = Instant::now();
    for i in 0..n {
        store
            .append_resolved_at(
                1_000_000 + i, // one row per microsecond
                "user",
                actor,
                "GET",
                "/api/x",
                Content::Text(String::new()),
                &[],
                BTreeMap::new(),
            )
            .unwrap();
    }
    store.sync().unwrap();
    let write_s = t_write.elapsed().as_secs_f64();

    // "before" shape: any time-range query used to read every segment
    // record-by-record — a full count is exactly that cost
    let t = Instant::now();
    let full = store.count(&LogQuery::default()).unwrap();
    let full_scan_s = t.elapsed().as_secs_f64();
    assert_eq!(full, n);

    // "after" shape: the last 0.1% of the time range
    let from = 1_000_000 + n - n / 1000;
    let q = LogQuery {
        from_micros: Some(from),
        ..Default::default()
    };
    let t = Instant::now();
    let narrow = store.count(&q).unwrap();
    let narrow_s = t.elapsed().as_secs_f64();
    assert_eq!(narrow, n / 1000);

    let total_segments = std::fs::read_dir(dir.path().join("logs"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".log")
        })
        .count() as u64;

    let t = Instant::now();
    let narrow_page = store
        .query_page(&LogQuery {
            from_micros: Some(from),
            limit: Some(100),
            ..Default::default()
        })
        .unwrap();
    let narrow_page_s = t.elapsed().as_secs_f64();
    assert_eq!(narrow_page.logs.len(), 100);

    let t = Instant::now();
    let latest_page = store
        .query_page(&LogQuery {
            limit: Some(100),
            ..Default::default()
        })
        .unwrap();
    let latest_page_s = t.elapsed().as_secs_f64();
    assert_eq!(latest_page.logs.len(), 100);

    println!("rows:                {n}");
    println!("write:               {write_s:.2}s ({:.0} rows/s)", n as f64 / write_s);
    println!("log segments:        {total_segments}");
    println!("full count:          {full_scan_s:.3}s  (= pre-pruning cost of ANY time-range query)");
    println!(
        "narrow count (0.1%): {narrow_s:.3}s  ({:.0}x faster)",
        full_scan_s / narrow_s
    );
    println!(
        "narrow page (100):   {narrow_page_s:.4}s, opened {}/{total_segments} segments",
        narrow_page.segments_scanned
    );
    println!(
        "latest-100 page:     {latest_page_s:.4}s, opened {}/{total_segments} segments",
        latest_page.segments_scanned
    );

    // the regression assertions: pruning must actually skip segments
    assert!(
        narrow_page.segments_scanned <= (total_segments / 10).max(2),
        "narrow window opened {} of {} segments",
        narrow_page.segments_scanned,
        total_segments
    );
    assert!(
        latest_page.segments_scanned <= 2,
        "latest-N page opened {} segments",
        latest_page.segments_scanned
    );
}
