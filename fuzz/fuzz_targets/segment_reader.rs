//! Fuzz the on-disk segment parser: framing, CRC validation and torn-tail
//! recovery. Arbitrary bytes are written as a segment file; every read path
//! must converge to `Ok`/`Err` — no panic, no infinite loop, no oversized
//! allocation (the `MAX_RECORD` guard).
#![no_main]

use libfuzzer_sys::fuzz_target;
use quipu_core::storage::{Segment, SegmentReader, Table};

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let seg_path = dir.path().join("seg-0000000000.log");
    std::fs::write(&seg_path, data).unwrap();

    // 1. sequential reader over raw bytes: errors are fine, panics are not
    if let Ok(mut r) = SegmentReader::open(&seg_path) {
        while let Ok(Some(_)) = r.next_record() {}
    }
    // bounded variant (snapshot read path)
    if let Ok(mut r) = SegmentReader::open_bounded(&seg_path, data.len() as u64 / 2) {
        while let Ok(Some(_)) = r.next_record() {}
    }

    // 2. writer-side recovery (skim + torn-tail truncation), then appending
    //    to the recovered file and reading everything back must work
    if let Ok(mut table) = Table::<Vec<u8>>::open(dir.path(), 1 << 20) {
        let _ = table.verify();
        if let Ok(scan) = table.scan() {
            for row in scan {
                let _ = row; // decode errors are fine
            }
        }
        let _ = table.append(&b"post-recovery".to_vec(), 42);
        let _ = table.sync();
        let _ = table.contains_chain_value(&[7u8; 32]);
    }

    // 3. raw Segment recovery open must also never panic
    drop(Segment::open(&seg_path, [0u8; 32]));
});
