# Quipu-Log

A quipu is the knotted-cord device the Incas used to keep records: knots tied
along a chain of cords, where you can't quietly retie one without it showing.
That's a pretty good picture of what this library does for your API.

Quipu-Log is an embedded audit log for Rust services. It records *who did what to
which entities through which API*, and lets you query it back later — including
by attribute values the entities had **at the time**. If a patient was renamed
last month, logs written before the rename still render the old name, and you
can still search by it.

Some things that make it different from "just log JSON somewhere":

- There is no database to run. Storage is an append-only segment store built
  on plain `std::fs` — CRC-framed records, crash recovery by truncating a torn
  tail. One dependency-free engine, same behavior on every OS.
- It's tamper-evident. Each record carries a SHA-256 hash chained to the
  previous one, across segment files. `store.verify_integrity()` catches
  records rewritten in place (even with a fixed-up CRC) and segments that were
  removed or swapped out.
- Writes don't block your handlers. Events go into a queue and a dedicated
  writer thread persists them, with retries, a disk-backed dead-letter queue,
  and a fallback hook you can point at your pager.
- Entities are versioned. Actors and targets live in per-type registries, and
  every log row pins the exact version that was current when it was written.

## Workspace layout

| crate | what it is |
|---|---|
| `quipu-core` | storage engine, typed registries, field encryption, retention, queries |
| `quipu-middleware` | event pipeline (DLQ/fallback), pre/post filters, permissions, `tower` proxy layer |
| `examples/axum-demo` | runnable axum integration |

## The data model

A log row has the columns you'd expect — `log_id`, `timestamp` (UTC
microseconds), `actor`, `method`, `url`, `targets`, `content` — plus any custom
columns you register (text / number / json, validated on every write).

`targets` is a relation table (`log_id`, `entity_registry_uid`, `entity_type`),
so a log can point at one entity or many. Targets *and actors* both live in
per-type registry tables, and you decide the field layout per type:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

(`default_target` and `default_actor` ship out of the box if you don't need
custom schemas.)

Each field picks its own protection level:

- `Sha256` — one-way hash that is still searchable, because query probes get
  hashed the same way. No key to manage. The catch: low-entropy values like
  SSNs can be brute-forced from disk, so use `Hmac` for those.
- `Hmac` — keyed HMAC-SHA-256 (`KeyRing::with_hmac_key`). Searchable like
  `Sha256`, but worthless to anyone who doesn't hold the key.
- `Rsa` — hybrid AES-256-GCM with RSA-OAEP key wrapping. Decryptable with the
  private key, not searchable, and authenticated — an in-place edit makes
  decryption fail.

Redefining a type is additive only. You can add fields, but existing fields
can't be removed or change kind/protection; allowing that would silently break
the "past values stay searchable" promise.

### How a write actually lands

1. `define_type` creates the registry table for a type (once).
2. Every write upserts the actor/target entities into their registries. If any
   field changed, that produces a new immutable version.
3. The log row stores the actor's version uid, and relation rows bind the log
   to the exact target versions.

Versions are immutable and indexed, which is what makes the time-travel part
work: rename an entity and both its old and new names stay searchable, while
every existing log keeps rendering values exactly as they were recorded.

## Recording through the HTTP proxy

The usual setup is a `tower` layer in front of your routes:

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

You can also skip HTTP entirely and emit events yourself:

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

Every hit comes back with actor/target snapshots as they were recorded, plus
an RFC 3339 UTC timestamp.

One caveat worth knowing about: `contains()` (substring) search always works on
plain fields, but on *protected* fields it needs an explicit opt-in via
`StoreConfig::plaintext_cache(true)`. With the cache on, RSA values are
decrypted with the private key and cached in memory per immutable version, and
hashed fields keep their plaintexts in memory for values written by the
current process (never persisted — after a restart, hashed fields fall back to
exact-match only). With the cache off — the default — a Contains query on a
protected field is rejected outright, rather than silently holding plaintexts
in memory without you asking for it.

Queries run against a read snapshot (`handle.snapshot(&role)?` /
`store.snapshot()?`). Taking one only clones the small in-memory registry
indexes, and the scan runs on the caller's thread, so a slow full-scan query
never gets in the way of event persistence.

### Browsing the registry

```rust
handle.entity_types(&role)?;                            // all type schemas
handle.list_entities(&role, "default_target", false)?;  // latest version per entity
handle.entity_history(&role, "default_target", "doc-1")?; // every version, oldest first
```

## Operational notes

- **Permissions** — role-based `Emit` / `Query` / `Administer` grants, in
  allowlist or denylist mode.
- **Retention** — `RetentionPolicy::days(90)` drops old data by deleting whole
  sealed segments: one `unlink`, no rewrites. Registries are kept so old
  history stays renderable.
- **Durability** — pick `SyncPolicy::Always` (fsync every write), `EveryN(n)`,
  or `OsManaged`.
- **DLQ** — events that exhaust their retries get parked on disk, survive
  restarts, and can be replayed with `handle.redrive_dlq(&admin_role)`.
  Redrive is crash-safe (failures are staged and made durable before the old
  queue is swapped out; delivery is at-least-once). Replayed logs keep the
  event's original occurrence time, and `required` custom columns aren't
  enforced retroactively, so old parked events always stay redrivable.
- **Single process only** — the store root is guarded by an OS file lock, so a
  second process opening the same root fails fast instead of corrupting it.
- **Integrity audit** — `store.verify_integrity()` walks every table's hash
  chain and reports the first record modified in place or segment swapped out.
- **Format versioning** — segment files start with a magic + version byte, so
  future layout changes can ship with migrations instead of misreads.
- Every write outcome is reported via `tracing`.

## Running the demo and tests

```sh
cargo test                 # core + middleware test suites
cargo run -p axum-demo     # then: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## License

Apache-2.0
