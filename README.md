# Quipu-Log

English | [한국어](README.ko.md)

**An embedded, tamper-evident audit log for Rust services.**

Quipu-Log records *who did what to which entities through which API*, and lets
you query it back later — including by attribute values the entities had **at
the time**. If a user was renamed last month, logs written before the rename
still render the old name, and you can still search by it.

> A *quipu* is the knotted-cord device the Incas used to keep records: knots
> tied along a chain of cords, where you can't quietly retie one without it
> showing. That's a good picture of what this library does for your API.

## Why not "just log JSON somewhere"?

- **No database to run.** Storage is an append-only segment store built on
  plain `std::fs`: CRC-framed records, crash recovery by truncating a torn
  tail. One dependency-free engine, same behavior on every OS.
- **Tamper-evident.** Each record carries a SHA-256 hash chained to the
  previous one, across segment files. `store.verify_integrity()` catches
  records rewritten in place (even with a fixed-up CRC) and segments that
  were removed or swapped out.
- **Writes don't block your handlers.** Events go into a queue and a
  dedicated writer thread persists them — with retries, a disk-backed
  dead-letter queue, and a fallback hook you can point at your pager.
- **Entities are versioned.** Actors and targets live in per-type registries,
  and every log row pins the exact version that was current when it was
  written. That's what makes time-travel queries work.

## Quick start

```rust
use quipu_core::*;
use quipu_middleware::*;

// 1. Open (or create) a store.
let root = std::path::PathBuf::from("/var/lib/myapp/audit");
let cfg = StoreConfig::new(&root)
    .retention(RetentionPolicy::days(90))
    .sync_policy(SyncPolicy::EveryN(32));
let mut store = AuditStore::open(cfg)?;

// 2. Register entity types (the defaults work without custom schemas).
if !store.has_type("default_actor") {
    store.define_type(default_actor_type())?;
    store.define_type(default_target_type())?;
}

// 3. Start the pipeline and keep a handle.
let pipeline = AuditPipeline::start(
    store, root, PermissionPolicy::allow_all(),
    PipelineConfig::default(), None /* fallback hook */)?;
let handle = pipeline.handle();

// 4. Emit events — non-blocking.
handle.emit(&Role::new("svc"), AuditEvent::new(...).target(...))?;
```

For HTTP services, skip step 4 and put the [`tower` proxy
layer](#recording-through-the-http-proxy) in front of your routes instead.
A complete runnable setup lives in [`examples/axum-demo`](examples/axum-demo).

## Workspace layout

| crate | what it is |
|---|---|
| `quipu-core` | storage engine, typed registries, field encryption, retention, queries |
| `quipu-middleware` | event pipeline (DLQ/fallback), pre/post filters, permissions, `tower` proxy layer |
| `quipu-server` | standalone daemon: the same store behind a token-authenticated HTTP/JSON API, for central multi-service deployments (see its [README](crates/quipu-server/README.md)) |
| `examples/axum-demo` | runnable axum integration |

## Data model

### Log rows and entities

A log row has the columns you'd expect: `log_id`, `timestamp` (UTC
microseconds), `actor`, `method`, `url`, `targets`, `content`, plus any custom
columns you register (text / number / json, validated on every write).

`targets` is a relation table (`log_id`, `entity_registry_uid`,
`entity_type`), so a log can point at one entity or many. Targets *and
actors* both live in per-type registry tables, and you decide the field
layout per type:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

`default_target` and `default_actor` ship out of the box if you don't need
custom schemas.

### Field protection

Each field picks its own protection level. The default is `None` — plaintext
on disk. Protection is opt-in per field; there is no store-wide switch.

| level | searchable? | key? | notes |
|---|---|---|---|
| `Sha256` | exact match | none | one-way hash; query probes are hashed the same way. Low-entropy values (SSNs) can be brute-forced from disk — use `Hmac` for those. |
| `Hmac` | exact match | `KeyRing::with_hmac_key` | keyed HMAC-SHA-256; worthless to anyone without the key. |
| `Rsa` | no (decrypt-scan) | RSA keypair | hybrid AES-256-GCM with RSA-OAEP key wrapping; authenticated — an in-place edit makes decryption fail. |

**Scope.** Protection only covers registry *fields*. Everything else is
always plaintext: `entity_id`, the log's `method`/`url`/`content`, and custom
columns — those are what queries filter and render on. The practical
consequence: model sensitive values as protected registry fields, and keep
them out of `entity_id` (use an opaque id, not an SSN) and out of `content`
(the request/response dump is the easiest place to leak PII by accident).

### Searching protected fields: blind indexes

Protection decides what a query can do: hashed fields are exact-match only,
RSA fields need a full decrypt-scan. If a protected field needs richer search
than that, give it a *blind index*:

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // exact match
    .search(FieldIndex::Ngram(3)),      // + substring match
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + prefix match up to 4 chars
```

At write time, while the plaintext is still in hand, lowercased tokens are
digested and persisted next to the record — `Exact` digests the whole value,
`Prefix(n)` its first 1..=n chars, `Ngram(n)` its n-char windows. The search
keeps working across restarts even though the plaintext never hits disk.

Token digests are domain-separated from the field's own digest and use the
same key discipline as the field (keyed fields get keyed tokens), so they add
no offline brute-force surface beyond what you declared. What they *do* leak
is structure: which stored values share prefixes or fragments. Declaring an
index is choosing that trade, per field — that's why there's no global
switch.

### Schema evolution

Redefining a type is additive only. You can add fields, but existing fields
can't be removed or change kind/protection/search index; allowing that would
silently break the "past values stay searchable" promise.

### How a write actually lands

1. `define_type` creates the registry table for a type (once).
2. Every write upserts the actor/target entities into their registries. If
   any field changed, that produces a new immutable version.
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

## Server mode: central deployments

Everything above runs *embedded* — the store lives inside your service's
process. `quipu-server` is a second way to run the same engine: a standalone
daemon that wraps the store in the async pipeline and exposes it over a
token-authenticated HTTP/JSON API, so multiple services — in any language —
can record and search audit logs centrally (the Elasticsearch-style
deployment shape).

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

The store stays single-process; the daemon is that process. Auth is
deny-by-default with per-token role grants, and the server can run
*write-only* — without the RSA private key it stores encrypted fields but
returns them as ciphertext for clients to decrypt locally, keeping plaintext
recovery out of the server's blast radius.

Configuration, the full HTTP API, and v1 limits are documented in the
[quipu-server README](crates/quipu-server/README.md).

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

### Match operators

Besides `exact` and `contains()` there are `prefix()` and `exact_ci()`
(case-insensitive exact). On protected fields they need the matching
`FieldIndex` declared (`Prefix(n)` / `Exact`) and then match with no false
positives.

How `contains()` resolves depends on the field:

- **Plain fields** — always works: an in-memory scan, or candidate-narrowed
  when an `Ngram` index is declared.
- **Protected fields with an `Ngram(n)` index** — probes of at least n chars
  match by token digests, case-insensitively, with no plaintext involved.
  For RSA fields the candidates are then decrypted and verified (this needs
  `StoreConfig::plaintext_cache(true)` and turns the full decrypt-scan into
  a candidate-scan). For one-way hashed fields there's no plaintext to
  verify against, so a hit means "carries all the probe's fragments" —
  false positives are possible; pair with `Rsa` when hits must be exact.
- **Protected fields without an index** — the legacy fallback: opt in via
  `StoreConfig::plaintext_cache(true)`, which decrypts-and-caches RSA values
  in memory and keeps hashed fields' plaintexts for values written by the
  current process (never persisted; after a restart those fall back to
  exact-match only). With the cache off — the default — the query is
  rejected outright, rather than silently holding plaintexts in memory
  without you asking for it.

### Snapshots

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
- **Retention** — `RetentionPolicy::days(90)` drops old data by deleting
  whole sealed segments: one `unlink`, no rewrites. Registries are kept so
  old history stays renderable.
- **Durability** — pick `SyncPolicy::Always` (fsync every write),
  `EveryN(n)`, or `OsManaged`.
- **Dead-letter queue** — events that exhaust their retries get parked on
  disk, survive restarts, and can be replayed with
  `handle.redrive_dlq(&admin_role)`. Redrive is crash-safe (failures are
  staged and made durable before the old queue is swapped out; delivery is
  at-least-once). Replayed logs keep the event's original occurrence time,
  and `required` custom columns aren't enforced retroactively, so old parked
  events always stay redrivable.
- **Single process only** — the store root is guarded by an OS file lock, so
  a second process opening the same root fails fast instead of corrupting it.
- **Integrity audit** — `store.verify_integrity()` walks every table's hash
  chain and reports the first record modified in place or segment swapped
  out.
- **Format versioning** — segment files start with a magic + version byte,
  so future layout changes can ship with migrations instead of misreads.
- **Observability** — every write outcome is reported via `tracing`.

## Running the demo and tests

```sh
cargo test                 # core + middleware test suites
cargo run -p axum-demo     # then: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## License

Apache-2.0
