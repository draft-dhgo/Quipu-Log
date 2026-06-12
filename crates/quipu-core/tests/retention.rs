use quipu_core::*;
use std::collections::BTreeMap;

fn open_store_with(root: &std::path::Path, retention: RetentionPolicy) -> AuditStore {
    let cfg = StoreConfig::new(root)
        .sync_policy(SyncPolicy::OsManaged)
        .max_segment_bytes(4 * 1024) // small segments -> many rolls
        .retention(retention);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn append_n(store: &mut AuditStore, n: usize) {
    let actor = EntityInput::new("user-1").text("name", "alice");
    for i in 0..n {
        store
            .append(
                "default_actor",
                &actor,
                "POST",
                &format!("/api/items/{i}"),
                Content::Text("x".repeat(512)), // pad so segments fill up fast
                &[],
                BTreeMap::new(),
            )
            .unwrap();
    }
    store.sync().unwrap();
}

#[test]
fn max_bytes_drops_oldest_segments_and_keeps_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let budget = 16 * 1024;
    let mut store = open_store_with(
        dir.path(),
        RetentionPolicy::keep_forever().with_max_bytes(budget),
    );
    append_n(&mut store, 200);

    let before = store.retained_bytes().unwrap();
    assert!(before > budget, "test setup must exceed the budget");

    let dropped = store.apply_retention().unwrap();
    assert!(dropped > 0, "over-budget store must drop segments");

    let after = store.retained_bytes().unwrap();
    assert!(after < before);
    // budget is a target: only active segments may keep it above the line,
    // and ours are capped at 4 KiB each (logs + relations)
    assert!(
        after <= budget + 2 * 4 * 1024,
        "after={after} budget={budget}"
    );

    // oldest data is gone, newest survives (active segment is never dropped)
    let hits = store.query(&LogQuery::default()).unwrap();
    assert!(!hits.is_empty());
    assert!(
        hits.iter().all(|h| h.url != "/api/items/0"),
        "oldest purged"
    );
    assert!(
        hits.iter().any(|h| h.url == "/api/items/199"),
        "newest kept"
    );

    // whole-segment drops must not break the tamper-evidence chain
    store.verify_integrity().unwrap();
}

#[test]
fn limits_combine_as_or_bytes_triggers_despite_long_age_window() {
    let dir = tempfile::tempdir().unwrap();
    // generous age window + tiny byte budget: OR semantics mean the byte
    // budget alone must trigger purging of fresh-but-bulky data
    let mut store = open_store_with(
        dir.path(),
        RetentionPolicy::days(3650).with_max_bytes(8 * 1024),
    );
    append_n(&mut store, 100);

    let dropped = store.apply_retention().unwrap();
    assert!(dropped > 0, "byte budget must purge even age-eligible data");
    store.verify_integrity().unwrap();
}

#[test]
fn no_limits_means_nothing_is_purged() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store_with(dir.path(), RetentionPolicy::keep_forever());
    append_n(&mut store, 50);
    assert_eq!(store.apply_retention().unwrap(), 0);
    assert_eq!(store.query(&LogQuery::default()).unwrap().len(), 50);
}

#[test]
fn age_only_policy_keeps_recent_data_regardless_of_size() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store_with(dir.path(), RetentionPolicy::days(7));
    append_n(&mut store, 100); // everything is seconds old
    assert_eq!(store.apply_retention().unwrap(), 0);
    assert_eq!(store.query(&LogQuery::default()).unwrap().len(), 100);
}
