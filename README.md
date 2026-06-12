# audit-logger

Embedded audit-logging middleware for Rust services. Record *who did what to
which entities through which API*, then query it back — including by attribute
values the entities had **in the past**.

- **No external database.** A purpose-built append-only segment store
  (`std::fs` only, CRC-framed records, crash recovery by tail truncation)
  keeps writes fast and the engine OS-independent.
- **Tamper-evident.** Every record carries a SHA-256 hash chained to the one
  before it, across segment files; `store.verify_integrity()` detects records
  rewritten in place (even with a fixed-up CRC) and removed/replaced segments.
- **Async by design.** Your handlers enqueue events and move on; a dedicated
  writer thread persists them with retries, a disk-backed **dead-letter queue**
  and a programmable **fallback hook**.
- **Time-travel entity registry.** Targets and actors are versioned per type;
  logs reference the exact version that was current at record time.

## Layout

| crate | what it is |
|---|---|
| `audit-core` | storage engine, typed registries, field encryption, retention, queries |
| `audit-middleware` | event pipeline (DLQ/fallback), pre/post filters, permissions, `tower` proxy layer |
| `examples/axum-demo` | runnable axum integration |

## The data model

Audit log columns: `log_id`, `timestamp` (UTC+0 microseconds), `actor`,
`method`, `url`, `targets`, `content` — plus any **custom columns** you
register (text / number / json, validated on every write).

`targets` is a relation table (`log_id`, `entity_registry_uid`,
`entity_type`); a log can point at one entity or many. Both targets *and
actors* live in **per-type registry tables** whose field layout you define:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

`default_target` and `default_actor` example types (indexed `name`, etc.) ship
out of the box. Field protection per field:

- `Sha256` — one-way hash; **still searchable** (probes are hashed too). No
  key to manage, but low-entropy values (SSNs, ...) can be brute-forced from
  disk — prefer `Hmac` for those
- `Hmac` — keyed HMAC-SHA-256 (`KeyRing::with_hmac_key`); searchable like
  `Sha256`, but useless to an attacker without the key
- `Rsa` — hybrid AES-256-GCM + RSA-OAEP key wrapping; decryptable with the
  private key, not searchable, authenticated (in-place edits fail decryption)

Redefining a type is **additive only**: new fields may be added, but existing
fields cannot be removed or change kind/protection — that would silently break
the "past values stay searchable" promise.

### The write protocol

1. `define_type` creates the registry table for a type (once),
2. each write upserts the actor/target entities into their registries —
   changed fields produce a **new immutable version**,
3. the log row stores the actor's version uid; relation rows bind the log to
   the exact target versions.

Because versions are immutable and indexed, renaming an entity keeps **both**
its current and past names searchable, while every log keeps rendering the
values exactly as they were when it was recorded.

## Recording through the HTTP proxy

```rust
let pipeline = AuditPipeline::start(store, root, permissions, PipelineConfig::default(),
    Some(Arc::new(|event, err| page_oncall(event, err))))?; // fallback
let layer = AuditLayer::new(pipeline.handle())
    .rules(vec![EndpointRule::prefix("/api/docs").method(Method::PUT)
        .capture_request().capture_response()        // bodies above the capture
        .capture_limit(1024 * 1024)                  //   limit proxy through uncaptured
        .target_extractor(|req, res, req_body, res_body| {
            /* rule-local target derivation (overrides the layer-wide one) */
            vec![]
        })])
    .filters(FilterSet::new()
        .pre(|req| /* runs before the handler: exempt health checks, ... */)
        .post(|req, res, event| /* runs after: skip 304s, enrich the event */))
    .target_extractor(|req, res, req_body, res_body| /* derive target entities */);
let app = Router::new().route(...).layer(layer);
```

Or emit events directly without HTTP:

```rust
handle.emit(&Role::new("svc"), AuditEvent::new(...).target(...))?;  // non-blocking
```

## Querying

```rust
let hits = handle.query(&Role::new("auditor"), LogQuery {
    targets: vec![          // several filters AND together
        // exact match, including past values (a renamed entity is still
        // found by its old name)
        TargetFilter::exact("default_target", "name", Value::Text("final-report".into())),
        // LIKE-style substring match
        TargetFilter::exact("default_target", "name", Value::Text("report".into())).contains(),
    ],
    method: Some("PUT".into()),
    ..Default::default()
})?;
```

Every hit carries actor/target **snapshots as recorded** and an RFC 3339 UTC
timestamp.

`contains()` (LIKE) search always works on plain fields. For *protected*
fields it requires opting in with `StoreConfig::plaintext_cache(true)`:
RSA values are then decrypted with the private key and cached in memory per
immutable version, and hashed fields written *by the current process* keep
their plaintexts in memory (never persisted — after a restart hashed fields
fall back to exact-match only). With the cache disabled (the default),
Contains on a protected field is rejected instead of silently holding
plaintexts in memory.

Queries run against a **read snapshot** (`handle.snapshot(&role)?` /
`store.snapshot()?`): taking one only clones the small in-memory registry
indexes, and the scan then runs on the caller's thread — a slow full-scan
query never blocks event persistence.

### Browsing the registry

```rust
handle.entity_types(&role)?;                            // all type schemas
handle.list_entities(&role, "default_target", false)?;  // latest version per entity
handle.entity_history(&role, "default_target", "doc-1")?; // every version, oldest first
```

## Operations

- **Permissions** — role-based `Emit` / `Query` / `Administer` grants,
  allowlist or denylist mode.
- **Retention** — `RetentionPolicy::days(90)`: old data is dropped by deleting
  whole sealed segments (one `unlink`, no rewrites). Registries are kept so
  history stays renderable.
- **Durability** — `SyncPolicy::Always` (fsync every write), `EveryN(n)`, or
  `OsManaged`.
- **DLQ** — events that exhaust retries are parked on disk, survive restarts,
  and are replayed with `handle.redrive_dlq(&admin_role)`. Redrive is
  crash-safe (failures are staged and made durable before the old queue is
  swapped out; delivery is at-least-once). Logs keep the event's original
  occurrence time, and `required` custom columns are not enforced
  retroactively, so old parked events always stay redrivable.
- **Result logging** — every write outcome is reported via `tracing`.
- **Single process** — the store root is guarded by an OS file lock; a second
  process opening the same root fails fast instead of corrupting it.
- **Integrity audit** — `store.verify_integrity()` walks every table's hash
  chain and reports the first record modified in place or segment swapped out.
- **Format versioning** — segment files start with a magic + version byte, so
  future layout changes can ship with migrations instead of misreads.

## Run the demo & tests

```sh
cargo test                 # core + middleware test suites
cargo run -p axum-demo     # then: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## License

MIT OR Apache-2.0
