//! Fuzz the DLQ redrive path with a corrupt on-disk DLQ: arbitrary bytes
//! become the DLQ's segment file, then a real pipeline runs dlq_len +
//! redrive_dlq over it. Everything must come back as a report or an error —
//! never a worker panic, hang or runaway allocation. This also drives
//! `bincode::deserialize::<DlqEntry>` over attacker-controlled payloads.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quipu_core::{default_actor_type, default_target_type, AuditStore, StoreConfig, SyncPolicy};
use quipu_middleware::{AuditPipeline, PermissionPolicy, PipelineConfig, Role};

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let dlq_dir = dir.path().join("dlq");
    std::fs::create_dir_all(&dlq_dir).unwrap();
    std::fs::write(dlq_dir.join("seg-0000000000.log"), data).unwrap();

    let cfg = StoreConfig::new(dir.path()).sync_policy(SyncPolicy::OsManaged);
    let mut store = AuditStore::open(cfg).unwrap();
    store.define_type(default_actor_type()).unwrap();
    store.define_type(default_target_type()).unwrap();

    // a DLQ that is not even a valid table is an explicit start error — fine
    let Ok(pipeline) = AuditPipeline::start(
        store,
        dir.path().to_path_buf(),
        PermissionPolicy::allow_all(),
        PipelineConfig::default(),
        None,
    ) else {
        return;
    };
    let handle = pipeline.handle();
    let admin = Role::new("admin");
    let _ = handle.dlq_len(&admin);
    let _ = handle.redrive_dlq(&admin);
    let _ = handle.dlq_len(&admin);
    pipeline.shutdown();
});
