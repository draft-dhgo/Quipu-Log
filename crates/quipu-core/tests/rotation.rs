//! Key rotation: multi-version probes, per-record key versions and the
//! signed offline re-key pass.

use quipu_core::*;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Two RSA keypairs (PKCS#8 PEM) shared by every test — 2048-bit generation
/// is the slow part, not the point of these tests.
fn pems() -> &'static (String, String) {
    static PEMS: OnceLock<(String, String)> = OnceLock::new();
    PEMS.get_or_init(|| {
        let gen = || {
            rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
                .unwrap()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
                .to_string()
        };
        (gen(), gen())
    })
}

/// The ring as it was before the rotation: version-1 keys only.
fn ring_v1() -> KeyRing {
    KeyRing::new()
        .with_private_pem_version(1, &pems().0)
        .unwrap()
        .with_hmac_key_version(1, b"hmac-key-1")
        .unwrap()
}

/// The ring after a rotation: version 2 is active, version 1 is retained
/// read-side material.
fn ring_v1_v2() -> KeyRing {
    ring_v1()
        .with_private_pem_version(2, &pems().1)
        .unwrap()
        .with_hmac_key_version(2, b"hmac-key-2")
        .unwrap()
}

/// The ring after the version-1 RSA private key was destroyed post-re-key.
fn ring_v2_rsa_only() -> KeyRing {
    KeyRing::new()
        .with_private_pem_version(2, &pems().1)
        .unwrap()
        .with_hmac_key_version(1, b"hmac-key-1")
        .unwrap()
        .with_hmac_key_version(2, b"hmac-key-2")
        .unwrap()
}

fn open_store(root: &std::path::Path, keys: KeyRing) -> AuditStore {
    let cfg = StoreConfig::new(root)
        .keys(keys)
        .sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    if !store.has_type("default_actor") {
        store.define_type(default_actor_type()).unwrap();
        store
            .define_type(TypeSchema::new(
                "patient",
                vec![
                    FieldDef::text("ssn")
                        .protection(FieldProtection::Hmac)
                        .indexed()
                        .search(FieldIndex::Ngram(3)),
                    FieldDef::text("name")
                        .protection(FieldProtection::Rsa)
                        .search(FieldIndex::Prefix(4)),
                ],
            ))
            .unwrap();
    }
    store
}

fn record_patient(store: &mut AuditStore, id: &str, ssn: &str, name: &str) {
    let patient = EntityInput::new(id).text("ssn", ssn).text("name", name);
    store
        .append(
            "default_actor",
            &EntityInput::new("user-1").text("name", "alice"),
            "GET",
            &format!("/api/patients/{id}"),
            Content::Text(String::new()),
            &[("patient".into(), patient)],
            BTreeMap::new(),
        )
        .unwrap();
}

fn exact(field: &str, probe: &str) -> LogQuery {
    LogQuery {
        targets: vec![TargetFilter::exact(
            "patient",
            field,
            Value::Text(probe.into()),
        )],
        ..Default::default()
    }
}

fn contains(field: &str, probe: &str) -> LogQuery {
    LogQuery {
        targets: vec![
            TargetFilter::exact("patient", field, Value::Text(probe.into())).contains(),
        ],
        ..Default::default()
    }
}

fn prefix(field: &str, probe: &str) -> LogQuery {
    LogQuery {
        targets: vec![TargetFilter::exact("patient", field, Value::Text(probe.into())).prefix()],
        ..Default::default()
    }
}

fn key_version_of(store: &AuditStore, id: &str, field: &str) -> u32 {
    match store
        .entity_latest("patient", id)
        .unwrap()
        .fields
        .get(field)
        .unwrap()
    {
        StoredValue::Hmac { key_version, .. } => *key_version,
        StoredValue::Rsa { key_version, .. } => *key_version,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn rotation_keeps_old_records_searchable_and_decryptable() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path(), ring_v1());
        record_patient(&mut store, "p-1", "123-45-6789", "Kim Daehyeon");
        store.sync().unwrap();
    }

    // rotate: reopen with version 2 active, version 1 retained
    let mut store = open_store(dir.path(), ring_v1_v2());

    // (a) the old record still matches probes and still decrypts
    assert_eq!(store.query(&exact("ssn", "123-45-6789")).unwrap().len(), 1);
    assert_eq!(store.query(&contains("ssn", "45-67")).unwrap().len(), 1);
    assert_eq!(store.query(&prefix("name", "kim")).unwrap().len(), 1);
    let hits = store.query(&exact("ssn", "123-45-6789")).unwrap();
    let name = hits[0].targets[0].fields.get("name").unwrap();
    assert_eq!(store.decrypt(name).unwrap(), b"Kim Daehyeon");
    assert_eq!(key_version_of(&store, "p-1", "ssn"), 1);
    assert_eq!(key_version_of(&store, "p-1", "name"), 1);

    // (b) a new record is protected under the new key version...
    record_patient(&mut store, "p-2", "987-65-4321", "Lee Minji");
    assert_eq!(key_version_of(&store, "p-2", "ssn"), 2);
    assert_eq!(key_version_of(&store, "p-2", "name"), 2);

    // ...and both generations answer the same kinds of probes
    assert_eq!(store.query(&exact("ssn", "987-65-4321")).unwrap().len(), 1);
    assert_eq!(store.query(&contains("ssn", "87-65")).unwrap().len(), 1);
    assert_eq!(store.query(&prefix("name", "lee")).unwrap().len(), 1);

    store.verify_integrity().unwrap();
}

#[test]
fn checkpoints_signed_before_rotation_still_verify() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path(), ring_v1());
        record_patient(&mut store, "p-1", "123-45-6789", "Kim");
        let cp = store.checkpoint().unwrap().unwrap();
        assert_eq!(cp.key_version, 1);
    }
    let mut store = open_store(dir.path(), ring_v1_v2());
    // the old checkpoint verifies against the retained v1 public key, and a
    // new one is signed with the active v2 key
    store.verify_integrity().unwrap();
    let cp = store.checkpoint().unwrap().unwrap();
    assert_eq!(cp.key_version, 2);
    store.verify_integrity().unwrap();
}

#[test]
fn rekey_rewraps_rsa_values_and_reindexes_their_tokens() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path(), ring_v1());
        record_patient(&mut store, "p-1", "123-45-6789", "Kim Daehyeon");
        store.sync().unwrap();
    }

    // forced rotation after a (presumed) leak of the v1 RSA private key:
    // rotate, then re-key so v1 can be destroyed
    let mut store = open_store(dir.path(), ring_v1_v2());
    let event = store.rekey().unwrap();
    assert_eq!(event.rsa_version, 2);
    assert_eq!(event.hmac_version, 2);
    assert_eq!(event.signing_key_version, 2);
    let patient = event
        .tables
        .iter()
        .find(|t| t.type_name == "patient")
        .unwrap();
    assert!(patient.records > 0);
    assert_ne!(
        patient.old_chain_head, patient.new_chain_head,
        "re-wrapped values must produce a chain transition"
    );

    // (c) the re-key itself passes integrity verification
    store.verify_integrity().unwrap();

    // RSA values now name version 2; HMAC digests keep their version (one-way)
    assert_eq!(key_version_of(&store, "p-1", "name"), 2);
    assert_eq!(key_version_of(&store, "p-1", "ssn"), 1);
    drop(store);

    // the v1 RSA private key can now be destroyed: a ring holding only the
    // v2 keypair still decrypts, searches and verifies everything
    let mut store = open_store(dir.path(), ring_v2_rsa_only());
    store.verify_integrity().unwrap();
    let hits = store.query(&exact("ssn", "123-45-6789")).unwrap();
    assert_eq!(hits.len(), 1, "old HMAC digests match via the retained v1 HMAC key");
    let name = hits[0].targets[0].fields.get("name").unwrap();
    assert_eq!(store.decrypt(name).unwrap(), b"Kim Daehyeon");
    // the RSA field's tokens were re-digested under HMAC v2 at re-key time
    assert_eq!(store.query(&prefix("name", "kim")).unwrap().len(), 1);

    // appends keep working on the rewritten chain
    record_patient(&mut store, "p-2", "987-65-4321", "Lee Minji");
    store.verify_integrity().unwrap();
}

#[test]
fn rekey_requires_old_private_keys_and_a_signer() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path(), ring_v1());
        record_patient(&mut store, "p-1", "123-45-6789", "Kim");
        store.sync().unwrap();
    }
    // v2 only: the v1 wrapped keys cannot be unwrapped -> explicit error,
    // and the store is left on its original, still-valid chain
    let mut store = open_store(dir.path(), ring_v2_rsa_only());
    let err = store.rekey().unwrap_err();
    assert!(err.to_string().contains("version 1"), "{err}");
    drop(store);
    let mut store = open_store(dir.path(), ring_v1_v2());
    store.verify_integrity().unwrap();
    assert_eq!(store.query(&exact("ssn", "123-45-6789")).unwrap().len(), 1);
}

#[test]
fn unaudited_registry_rewrite_after_rekey_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut store = open_store(dir.path(), ring_v1());
        record_patient(&mut store, "p-1", "123-45-6789", "Kim");
        store.sync().unwrap();
    }
    {
        let mut store = open_store(dir.path(), ring_v1_v2());
        store.rekey().unwrap();
        store.verify_integrity().unwrap();
    }

    // an insider replaces the re-keyed registry with a self-consistent
    // rewrite (fresh chain): every per-record check passes, but the chain
    // head signed by the re-key event is gone
    std::fs::remove_dir_all(dir.path().join("registry").join("patient")).unwrap();
    let mut store = open_store(dir.path(), ring_v1_v2());
    record_patient(&mut store, "p-1", "123-45-6789", "Kim");
    let err = store.verify_integrity().unwrap_err();
    assert!(err.to_string().contains("re-key"), "{err}");
}
