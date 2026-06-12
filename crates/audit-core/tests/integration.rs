use audit_core::*;
use std::collections::BTreeMap;

fn open_store(root: &std::path::Path) -> AuditStore {
    let cfg = StoreConfig::new(root).sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store.define_type(default_target_type()).unwrap();
    }
    store
}

fn alice() -> EntityInput {
    EntityInput::new("user-1")
        .text("name", "alice")
        .text("role", "admin")
}

#[test]
fn rename_keeps_history_searchable_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());

    // log an update against a document named "draft"
    let doc = EntityInput::new("doc-9").text("name", "draft");
    store
        .append(
            "default_actor",
            &alice(),
            "PUT",
            "/api/docs/9",
            Content::Text("update #1".into()),
            &[("default_target".into(), doc)],
            BTreeMap::new(),
        )
        .unwrap();

    // rename the document, then log another update
    let doc2 = EntityInput::new("doc-9").text("name", "final-report");
    store
        .append(
            "default_actor",
            &alice(),
            "PUT",
            "/api/docs/9",
            Content::Text("update #2".into()),
            &[("default_target".into(), doc2)],
            BTreeMap::new(),
        )
        .unwrap();

    let by = |store: &mut AuditStore, name: &str| -> Vec<LogView> {
        store
            .query(&LogQuery {
                targets: vec![TargetFilter::exact(
                    "default_target",
                    "name",
                    Value::Text(name.into()),
                )],
                ..Default::default()
            })
            .unwrap()
    };

    // current name and past name both find ALL logs of the entity
    let current = by(&mut store, "final-report");
    let past = by(&mut store, "draft");
    assert_eq!(current.len(), 2);
    assert_eq!(past.len(), 2);

    // but each log renders the name as it was at record time
    let name_of = |v: &LogView| match v.targets[0].fields.get("name").unwrap() {
        StoredValue::Plain(Value::Text(s)) => s.clone(),
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(name_of(&current[0]), "draft");
    assert_eq!(name_of(&current[1]), "final-report");

    // unrelated name finds nothing
    assert!(by(&mut store, "nope").is_empty());
}

#[test]
fn survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path());
        store
            .append(
                "default_actor",
                &alice(),
                "DELETE",
                "/api/things/3",
                Content::Json(serde_json::json!({"status": 204})),
                &[(
                    "default_target".into(),
                    EntityInput::new("thing-3").text("name", "widget"),
                )],
                BTreeMap::new(),
            )
            .unwrap();
        store.sync().unwrap();
    }
    let mut store = open_store(dir.path());
    let hits = store
        .query(&LogQuery {
            method: Some("DELETE".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].url, "/api/things/3");
    assert_eq!(hits[0].targets[0].entity_id, "thing-3");
    assert!(hits[0].timestamp.ends_with('Z'));
}

#[test]
fn custom_columns_validated_and_queryable() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    store
        .define_custom_column(CustomColumnDef::new("tenant", ValueKind::Text))
        .unwrap();

    // wrong kind is rejected
    let mut bad = BTreeMap::new();
    bad.insert("tenant".to_string(), Value::Number(7.0));
    assert!(store
        .append(
            "default_actor",
            &alice(),
            "GET",
            "/x",
            Content::Text("".into()),
            &[],
            bad
        )
        .is_err());

    // unknown column is rejected
    let mut unknown = BTreeMap::new();
    unknown.insert("nope".to_string(), Value::Text("v".into()));
    assert!(store
        .append(
            "default_actor",
            &alice(),
            "GET",
            "/x",
            Content::Text("".into()),
            &[],
            unknown
        )
        .is_err());

    let mut ok = BTreeMap::new();
    ok.insert("tenant".to_string(), Value::Text("acme".into()));
    store
        .append(
            "default_actor",
            &alice(),
            "GET",
            "/x",
            Content::Text("".into()),
            &[],
            ok.clone(),
        )
        .unwrap();

    let hits = store
        .query(&LogQuery {
            custom: ok,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
}

#[test]
fn hashed_fields_stay_searchable_rsa_fields_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyRing::generate_ephemeral(2048).unwrap();
    let cfg = StoreConfig::new(dir.path())
        .keys(keys)
        .sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store
        .define_type(TypeSchema::new(
            "patient",
            vec![
                FieldDef::text("ssn")
                    .protection(FieldProtection::Hmac)
                    .indexed()
                    .required(),
                FieldDef::text("mrn")
                    .protection(FieldProtection::Sha256)
                    .indexed(),
                FieldDef::text("name").protection(FieldProtection::Rsa),
            ],
        ))
        .unwrap();

    let patient = EntityInput::new("p-1")
        .text("ssn", "123-45-6789")
        .text("mrn", "MRN-001")
        .text("name", "Kim");
    store
        .append(
            "default_actor",
            &alice(),
            "GET",
            "/api/patients/p-1",
            Content::Text("viewed record".into()),
            &[("patient".into(), patient)],
            BTreeMap::new(),
        )
        .unwrap();

    // hashed field: search by plaintext probe works, plaintext not on disk
    let hits = store
        .query(&LogQuery {
            targets: vec![TargetFilter::exact(
                "patient",
                "ssn",
                Value::Text("123-45-6789".into()),
            )],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);
    let snap = &hits[0].targets[0];
    assert!(matches!(
        snap.fields.get("ssn").unwrap(),
        StoredValue::Hmac(_)
    ));
    assert!(matches!(
        snap.fields.get("mrn").unwrap(),
        StoredValue::Sha256(_)
    ));

    // keyless sha256 field: plaintext probe search also works
    let hits = store
        .query(&LogQuery {
            targets: vec![TargetFilter::exact(
                "patient",
                "mrn",
                Value::Text("MRN-001".into()),
            )],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(hits.len(), 1);

    // rsa field decrypts with the private key
    let name = snap.fields.get("name").unwrap();
    assert!(matches!(name, StoredValue::Rsa { .. }));
    assert_eq!(store.decrypt(name).unwrap(), b"Kim");
}

#[test]
fn deleted_entity_history_remains() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    store
        .append(
            "default_actor",
            &alice(),
            "POST",
            "/api/items",
            Content::Text("created".into()),
            &[(
                "default_target".into(),
                EntityInput::new("it-1").text("name", "gizmo"),
            )],
            BTreeMap::new(),
        )
        .unwrap();
    store.delete_entity("default_target", "it-1").unwrap();

    // past-name search still finds the log; latest-only search does not
    let mk = |include_past: bool| {
        let mut f = name_filter("gizmo");
        f.include_past = include_past;
        LogQuery {
            targets: vec![f],
            ..Default::default()
        }
    };
    assert_eq!(store.query(&mk(true)).unwrap().len(), 1);
    assert_eq!(store.query(&mk(false)).unwrap().len(), 0);
}

fn name_filter(name: &str) -> TargetFilter {
    TargetFilter::exact("default_target", "name", Value::Text(name.into()))
}

#[test]
fn multiple_target_filters_are_anded() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    let mut log = |targets: &[&str]| {
        let targets: Vec<(String, EntityInput)> = targets
            .iter()
            .map(|n| {
                (
                    "default_target".to_string(),
                    EntityInput::new(format!("id-{n}")).text("name", *n),
                )
            })
            .collect();
        store
            .append(
                "default_actor",
                &alice(),
                "POST",
                "/api/batch",
                Content::Text("".into()),
                &targets,
                BTreeMap::new(),
            )
            .unwrap();
    };
    log(&["a", "b"]);
    log(&["a"]);
    log(&["b", "c"]);

    let q = |names: &[&str]| LogQuery {
        targets: names.iter().map(|n| name_filter(n)).collect(),
        ..Default::default()
    };
    assert_eq!(store.query(&q(&["a"])).unwrap().len(), 2);
    assert_eq!(
        store.query(&q(&["a", "b"])).unwrap().len(),
        1,
        "AND of both targets"
    );
    assert_eq!(store.query(&q(&["a", "c"])).unwrap().len(), 0);
}

#[test]
fn second_open_of_same_root_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    let err = match AuditStore::open(StoreConfig::new(dir.path())) {
        Err(e) => e,
        Ok(_) => panic!("second open of the same root must fail"),
    };
    assert!(
        matches!(err, Error::Locked(_)),
        "expected Locked, got {err}"
    );
    drop(store);
    // lock is released on drop
    open_store(dir.path());
}

#[test]
fn type_redefinition_guard_rejects_breaking_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());

    // additive change is fine
    store
        .define_type(TypeSchema::new(
            "default_target",
            vec![
                FieldDef::text("name").indexed().required(),
                FieldDef::text("description"),
                FieldDef::text("owner"),
            ],
        ))
        .unwrap();

    // changing protection of an existing field would split the search index
    let err = store
        .define_type(TypeSchema::new(
            "default_target",
            vec![
                FieldDef::text("name")
                    .protection(FieldProtection::Sha256)
                    .indexed()
                    .required(),
                FieldDef::text("description"),
                FieldDef::text("owner"),
            ],
        ))
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot change kind/protection"),
        "{err}"
    );

    // dropping an existing field is rejected too
    let err = store
        .define_type(TypeSchema::new(
            "default_target",
            vec![FieldDef::text("name").indexed().required()],
        ))
        .unwrap_err();
    assert!(err.to_string().contains("cannot be removed"), "{err}");
}

#[test]
fn required_custom_column_is_not_retroactive() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    let before = audit_core::time::now_micros() - 1_000_000; // 1s in the past
    store
        .define_custom_column(CustomColumnDef::new("reason", ValueKind::Text).required())
        .unwrap();

    // an event that occurred before the column became required still writes
    store
        .append_at(
            before,
            "default_actor",
            &alice(),
            "GET",
            "/api/old-event",
            Content::Text("".into()),
            &[],
            BTreeMap::new(),
        )
        .unwrap();

    // a new event without the column is rejected
    assert!(store
        .append(
            "default_actor",
            &alice(),
            "GET",
            "/api/new",
            Content::Text("".into()),
            &[],
            BTreeMap::new()
        )
        .is_err());
}

#[test]
fn verify_integrity_detects_in_place_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    for i in 0..5 {
        store
            .append(
                "default_actor",
                &alice(),
                "POST",
                &format!("/api/x/{i}"),
                Content::Text("payload-payload".into()),
                &[],
                BTreeMap::new(),
            )
            .unwrap();
    }
    store.sync().unwrap();
    store.verify_integrity().unwrap();

    // flip one byte in the middle of the log segment while the store is open
    // (reopening would let torn-tail recovery truncate the evidence away; the
    // crc-fixed tampering case is covered by storage::segment unit tests)
    let seg = std::fs::read_dir(dir.path().join("logs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .unwrap();
    let mut bytes = std::fs::read(&seg).unwrap();
    // first byte of the first record's payload: 37-byte segment header
    // (magic+version+seed) + 48-byte frame header (len+crc+ts+chain)
    bytes[37 + 48] ^= 0xff;
    std::fs::write(&seg, &bytes).unwrap();

    assert!(store.verify_integrity().is_err());
}

#[test]
fn unresolvable_registry_reference_renders_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path());
        store
            .append(
                "default_actor",
                &alice(),
                "GET",
                "/api/q",
                Content::Text("".into()),
                &[(
                    "default_target".into(),
                    EntityInput::new("t-1").text("name", "thing"),
                )],
                BTreeMap::new(),
            )
            .unwrap();
        store.sync().unwrap();
    }
    // simulate registry data loss: the target registry table disappears
    std::fs::remove_dir_all(dir.path().join("registry").join("default_target")).unwrap();

    let mut store = open_store(dir.path());
    let hits = store.query(&LogQuery::default()).unwrap();
    assert_eq!(hits.len(), 1, "the log must still be readable");
    assert!(
        hits[0].targets[0].missing,
        "lost reference renders as a placeholder"
    );
    assert!(!hits[0].actor.missing, "actor registry is intact");
}

#[test]
fn contains_search_matches_substrings_including_past_values() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    for name in ["draft-report", "final-report"] {
        store
            .append(
                "default_actor",
                &alice(),
                "PUT",
                "/api/docs/9",
                Content::Text("".into()),
                &[(
                    "default_target".into(),
                    EntityInput::new("doc-9").text("name", name),
                )],
                BTreeMap::new(),
            )
            .unwrap();
    }

    let q = |f: TargetFilter| LogQuery {
        targets: vec![f],
        ..Default::default()
    };
    let like = |s: &str| name_filter(s).contains();

    // substring matches across all versions of the entity -> both logs
    assert_eq!(store.query(&q(like("report"))).unwrap().len(), 2);
    // old value still matches with include_past...
    assert_eq!(store.query(&q(like("draft"))).unwrap().len(), 2);
    // ...but not against the latest version only
    assert_eq!(
        store.query(&q(like("draft").latest_only())).unwrap().len(),
        0
    );
    assert!(store.query(&q(like("nope"))).unwrap().is_empty());
}

#[test]
fn contains_search_on_protected_fields() {
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyRing::generate_ephemeral(2048).unwrap();
    let cfg = StoreConfig::new(dir.path())
        .keys(keys.clone())
        .plaintext_cache(true)
        .sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store
        .define_type(TypeSchema::new(
            "patient",
            vec![
                FieldDef::text("ssn")
                    .protection(FieldProtection::Hmac)
                    .indexed(),
                FieldDef::text("name").protection(FieldProtection::Rsa),
            ],
        ))
        .unwrap();
    let patient = EntityInput::new("p-1")
        .text("ssn", "123-45-6789")
        .text("name", "Kim Daehyeon");
    store
        .append(
            "default_actor",
            &alice(),
            "GET",
            "/api/patients/p-1",
            Content::Text("".into()),
            &[("patient".into(), patient)],
            BTreeMap::new(),
        )
        .unwrap();
    store.sync().unwrap();

    let q = |field: &str, probe: &str| LogQuery {
        targets: vec![TargetFilter::exact("patient", field, Value::Text(probe.into())).contains()],
        ..Default::default()
    };

    // RSA field: decrypted (and cached) with the private key for LIKE search
    assert_eq!(store.query(&q("name", "Daehyeon")).unwrap().len(), 1);
    assert!(store.query(&q("name", "Someone")).unwrap().is_empty());

    // one-way hashed field: LIKE works because this process held the
    // plaintext in memory at write time
    assert_eq!(store.query(&q("ssn", "45-67")).unwrap().len(), 1);

    // ...but after a restart the plaintext is gone (it is never persisted):
    // LIKE finds nothing, exact search still works
    drop(store);
    let cfg = StoreConfig::new(dir.path())
        .keys(keys.clone())
        .plaintext_cache(true)
        .sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    assert!(store.query(&q("ssn", "45-67")).unwrap().is_empty());
    let exact = LogQuery {
        targets: vec![TargetFilter::exact(
            "patient",
            "ssn",
            Value::Text("123-45-6789".into()),
        )],
        ..Default::default()
    };
    assert_eq!(store.query(&exact).unwrap().len(), 1);
    // RSA LIKE keeps working after restart (decryptable from disk)
    assert_eq!(store.query(&q("name", "Daehyeon")).unwrap().len(), 1);

    // with the plaintext cache disabled (the default), LIKE on protected
    // fields is rejected outright instead of silently caching plaintexts
    drop(store);
    let cfg = StoreConfig::new(dir.path())
        .keys(keys)
        .sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    let err = store.query(&q("name", "Daehyeon")).unwrap_err();
    assert!(
        err.to_string().contains("plaintext cache is disabled"),
        "{err}"
    );
    assert_eq!(
        store.query(&exact).unwrap().len(),
        1,
        "exact match is unaffected"
    );
}

#[test]
fn registry_browsing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());

    let types = store.type_schemas();
    let names: Vec<&str> = types.iter().map(|t| t.type_name.as_str()).collect();
    assert_eq!(names, vec!["default_actor", "default_target"]);

    store
        .register_entity(
            "default_target",
            &EntityInput::new("doc-1").text("name", "alpha"),
        )
        .unwrap();
    store
        .register_entity(
            "default_target",
            &EntityInput::new("doc-1").text("name", "beta"),
        )
        .unwrap();
    store
        .register_entity(
            "default_target",
            &EntityInput::new("doc-2").text("name", "gamma"),
        )
        .unwrap();
    store.delete_entity("default_target", "doc-2").unwrap();

    // listing returns latest versions, deleted ones only on request
    let live = store.list_entities("default_target", false).unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].entity_id, "doc-1");
    assert_eq!(live[0].version, 1, "latest version after the rename");
    let all = store.list_entities("default_target", true).unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|e| e.entity_id == "doc-2" && e.deleted));

    // history: every version oldest-first, delete visible as the last one
    let history = store.entity_history("default_target", "doc-1").unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].fields.get("name"),
        Some(&StoredValue::Plain(Value::Text("alpha".into())))
    );
    assert_eq!(
        history[1].fields.get("name"),
        Some(&StoredValue::Plain(Value::Text("beta".into())))
    );
    let history = store.entity_history("default_target", "doc-2").unwrap();
    assert!(history.last().unwrap().deleted);

    assert!(store.entity_history("default_target", "ghost").is_err());
    assert!(store.list_entities("ghost_type", false).is_err());
}

#[test]
fn snapshot_queries_are_isolated_from_later_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = open_store(dir.path());
    let log = |store: &mut AuditStore, url: &str| {
        store
            .append(
                "default_actor",
                &alice(),
                "GET",
                url,
                Content::Text("".into()),
                &[],
                BTreeMap::new(),
            )
            .unwrap();
    };
    log(&mut store, "/api/a");
    let mut snap = store.snapshot().unwrap();
    log(&mut store, "/api/b");

    // the snapshot sees only what existed when it was taken; the live store
    // sees everything
    assert_eq!(snap.query(&LogQuery::default()).unwrap().len(), 1);
    assert_eq!(store.query(&LogQuery::default()).unwrap().len(), 2);
}
