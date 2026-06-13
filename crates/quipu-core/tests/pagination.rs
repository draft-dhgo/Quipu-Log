//! Cursor pagination, ordering, time-range pruning and count — the
//! scalable-query surface of the store.

use quipu_core::*;
use std::collections::BTreeMap;

fn open_store(root: &std::path::Path) -> AuditStore {
    // tiny segments so even small tests roll many files
    let cfg = StoreConfig::new(root)
        .sync_policy(SyncPolicy::OsManaged)
        .max_segment_bytes(4 * 1024);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn alice() -> EntityInput {
    EntityInput::new("user-1").text("name", "alice")
}

/// Append `n` logs with timestamps `start..start + n` (one per microsecond).
fn fill(store: &mut AuditStore, start: u64, n: u64) {
    for i in start..start + n {
        store
            .append_at(
                i,
                "default_actor",
                &alice(),
                "GET",
                &format!("/api/things/{i}"),
                Content::Text(format!("event-{i}")),
                &[(
                    "default_target".into(),
                    EntityInput::new(format!("thing-{}", i % 7)).text("name", format!("t{}", i % 7)),
                )],
                BTreeMap::new(),
            )
            .unwrap();
    }
    store.sync().unwrap();
}

fn drain(store: &mut AuditStore, base: &LogQuery) -> Vec<u64> {
    let mut q = base.clone();
    let mut out = Vec::new();
    loop {
        let page = store.query_page(&q).unwrap();
        out.extend(page.logs.iter().map(|v| v.timestamp_micros));
        match page.next_cursor {
            Some(c) => q.cursor = Some(c),
            None => return out,
        }
    }
}

#[test]
fn desc_default_returns_latest_n() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 200);

    let page = store
        .query_page(&LogQuery {
            limit: Some(10),
            ..Default::default()
        })
        .unwrap();
    let ts: Vec<u64> = page.logs.iter().map(|v| v.timestamp_micros).collect();
    assert_eq!(ts, (191..=200).rev().collect::<Vec<_>>());
    assert!(page.next_cursor.is_some());
}

#[test]
fn cursor_walks_everything_without_dups_or_gaps_both_orders() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 200);

    for order in [Order::Desc, Order::Asc] {
        let got = drain(
            &mut store,
            &LogQuery {
                limit: Some(7), // page size that does not divide 200
                order,
                ..Default::default()
            },
        );
        let want: Vec<u64> = match order {
            Order::Asc => (1..=200).collect(),
            Order::Desc => (1..=200).rev().collect(),
        };
        assert_eq!(got, want, "order {order:?}");
    }
}

#[test]
fn cursor_survives_concurrent_appends() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 100);

    // first page of the newest-first listing
    let mut q = LogQuery {
        limit: Some(10),
        ..Default::default()
    };
    let page = store.query_page(&q).unwrap();
    let first: Vec<u64> = page.logs.iter().map(|v| v.timestamp_micros).collect();
    assert_eq!(first, (91..=100).rev().collect::<Vec<_>>());
    q.cursor = page.next_cursor;

    // records appended *after* the cursor was issued sort strictly after it
    // in append order, so a desc continuation never sees them: the listing
    // the user started stays stable (no shifted duplicates, no holes)
    fill(&mut store, 101, 50);

    let rest = drain(&mut store, &q);
    assert_eq!(rest, (1..=90).rev().collect::<Vec<_>>());

    // a *fresh* desc query does see the new records
    let fresh = store
        .query_page(&LogQuery {
            limit: Some(1),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(fresh.logs[0].timestamp_micros, 150);
}

#[test]
fn time_range_pruning_skips_segments() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 500);

    // full scan opens every log segment
    let full = store.query_page(&LogQuery::default()).unwrap();
    let total_segments = full.segments_scanned;
    assert!(total_segments > 3, "test needs several segments");

    // a narrow window must open only the overlapping segment(s)
    let narrow = store
        .query_page(&LogQuery {
            from_micros: Some(490),
            to_micros: Some(500),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(narrow.logs.len(), 11);
    assert!(
        narrow.segments_scanned < total_segments / 2,
        "pruning opened {} of {} segments",
        narrow.segments_scanned,
        total_segments
    );
}

#[test]
fn count_matches_query_and_ignores_limit() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 120);

    let q = LogQuery {
        from_micros: Some(21),
        to_micros: Some(80),
        limit: Some(5),
        ..Default::default()
    };
    assert_eq!(store.count(&q).unwrap(), 60);
    assert_eq!(store.query(&q).unwrap().len(), 5);

    // count with a target filter agrees with the rendered result set
    let q = LogQuery {
        targets: vec![TargetFilter::exact(
            "default_target",
            "name",
            Value::Text("t3".into()),
        )],
        ..Default::default()
    };
    let n = store.count(&q).unwrap();
    assert_eq!(n, store.query(&q).unwrap().len() as u64);
    assert!(n > 0);
}

#[test]
fn pagination_is_consistent_under_target_filter() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 140);

    let base = LogQuery {
        targets: vec![TargetFilter::exact(
            "default_target",
            "name",
            Value::Text("t2".into()),
        )],
        ..Default::default()
    };
    let all: Vec<u64> = store
        .query(&base)
        .unwrap()
        .iter()
        .map(|v| v.timestamp_micros)
        .collect();
    assert_eq!(all.len(), 20);

    let mut paged_q = base.clone();
    paged_q.limit = Some(3);
    let paged = drain(&mut store, &paged_q);
    assert_eq!(paged, all, "paged traversal must equal the one-shot result");
}

#[test]
fn bad_cursors_are_client_errors() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 30);

    let garbage = store.query_page(&LogQuery {
        cursor: Some("not-a-cursor!!".into()),
        ..Default::default()
    });
    assert!(matches!(garbage, Err(Error::InvalidCursor(_))), "{garbage:?}");

    // a cursor issued under desc cannot continue an asc query
    let page = store
        .query_page(&LogQuery {
            limit: Some(5),
            ..Default::default()
        })
        .unwrap();
    let flipped = store.query_page(&LogQuery {
        order: Order::Asc,
        cursor: page.next_cursor,
        ..Default::default()
    });
    assert!(matches!(flipped, Err(Error::InvalidCursor(_))), "{flipped:?}");
}

#[test]
fn final_page_has_no_cursor_even_when_exactly_full() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    fill(&mut store, 1, 20);

    let page = store
        .query_page(&LogQuery {
            limit: Some(20),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(page.logs.len(), 20);
    assert!(page.next_cursor.is_none(), "no more matches → no cursor");
}
