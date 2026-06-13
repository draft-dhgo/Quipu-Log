//! Seed-corpus generator: writes structurally valid segment / DLQ files into
//! `fuzz/corpus/<target>/` so the fuzzer starts from real frames instead of
//! having to discover the magic + CRC format from scratch.
//!
//! Run from the `fuzz/` directory: `cargo run --bin gen_corpus`

use quipu_core::storage::Table;
use quipu_core::{Content, EntityInput};
use quipu_middleware::{AuditEvent, DlqEntry, TargetSpec};
use std::path::Path;

fn copy_segments(src_dir: &Path, corpus: &Path, prefix: &str) {
    std::fs::create_dir_all(corpus).unwrap();
    for entry in std::fs::read_dir(src_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "log") {
            let name = format!("{prefix}-{}", path.file_name().unwrap().to_string_lossy());
            std::fs::copy(&path, corpus.join(name)).unwrap();
        }
    }
}

fn main() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));

    // a small valid table of raw rows -> segment_reader corpus
    let dir = tempfile::tempdir().unwrap();
    let mut t: Table<Vec<u8>> = Table::open(dir.path(), 4096).unwrap();
    for i in 0..40u64 {
        t.append(&format!("row-{i}").into_bytes(), i).unwrap();
    }
    t.sync().unwrap();
    copy_segments(dir.path(), &base.join("corpus/segment_reader"), "table");

    // a valid DLQ with real parked events -> dlq_redrive corpus
    let dir = tempfile::tempdir().unwrap();
    let mut dlq: Table<DlqEntry> = Table::open(dir.path(), 1 << 20).unwrap();
    for i in 0..8u64 {
        let event = AuditEvent::new(
            "default_actor",
            EntityInput::new("svc-1").text("name", "svc"),
            "PUT",
            format!("/api/broken/{i}"),
            Content::Text("payload".into()),
        )
        .target(TargetSpec::new("ghost_type", EntityInput::new("g-1")));
        dlq.append(
            &DlqEntry {
                event,
                error: "schema missing".into(),
                failed_at: i,
            },
            i,
        )
        .unwrap();
    }
    dlq.sync().unwrap();
    copy_segments(dir.path(), &base.join("corpus/dlq_redrive"), "dlq");

    println!("corpus written under {}", base.join("corpus").display());
}
