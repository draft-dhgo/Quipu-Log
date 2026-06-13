# Quipu-Log

English | [한국어](README.ko.md)

**Tamper-evident audit logging for Rust services. Embedded — no database to run.**

Quipu-Log answers questions like *"who changed this document last quarter, and what was it called back then?"*

It records who did what to which entities through which API,
chains every record to the previous one so silent edits show up,
and remembers what each entity looked like at the moment a log was written.
Rename a user today and last month's logs still render — and still search — under the old name.

> The name comes from the *quipu*, the knotted-cord records of the Incas:
> knots tied along a chain of cords, hard to retie without leaving a trace.

## Why this exists

Most audit logging starts as "serialize something to JSON and ship it somewhere."
That works until the first real audit, which is when you discover three problems at once:
nothing stops anyone with file access from editing history;
the names and attributes embedded in old logs have gone stale or were never captured;
and "find every log about X" means grepping half-structured text.
Putting the logs in a database table fixes the third problem and leaves the other two.

Quipu-Log is what you get when you treat those as design requirements instead of incident retrospectives:

- **Tampering is detectable.**
  Storage is append-only, and every record carries a SHA-256 hash chained to the previous one across file boundaries.
  `store.verify_integrity()` pinpoints the first record rewritten in place or the segment swapped out — a fixed-up CRC doesn't fool it.
- **History keeps its context.**
  The people and things your logs mention are stored as versioned entities,
  so past logs keep rendering and matching the values that were true at write time.
- **Nothing else to operate.**
  The store is a directory managed through plain `std::fs` — CRC-framed records, crash recovery by truncating a torn tail.
  No daemon, no external dependency, same behavior on every OS.
- **Your handlers don't wait on disk.**
  Writes go through an async pipeline with retries, a disk-backed dead-letter queue,
  and a fallback hook you can point at your pager.

## How it works

Every audit record is an **event**:
an *actor* (who — a user, a service) did something (`method`, `url`, optional request/response content)
to one or more *targets* (what).

Actors and targets aren't free-form strings.
They are **entities**: structured records whose fields you define per **type**,
and each type gets its own **registry** inside the store.

Registries never overwrite.
When an entity's fields change, the registry adds a new immutable **version**,
and every log row pins the exact versions that were current when it was written.
That pinning is the entire trick behind time-travel queries —
old and new values both stay indexed, and each log renders the values it actually saw.

```
your handler ──emit──▶ pipeline ─────────▶ store (append-only, hash-chained)
              (non-    (queue, retries,     ├── logs
              blocking) DLQ, fallback)      └── registries (versioned entities)
```

Your code holds a cheap, cloneable **handle** to the pipeline;
a dedicated writer thread owns the store and does the persisting.

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

A complete runnable setup lives in [`examples/axum-demo`](examples/axum-demo).
For HTTP services you usually don't emit by hand — read on.

## Recording from HTTP

The usual setup is a `tower` layer in front of your routes.
It decides which endpoints to record, optionally captures bodies,
and derives target entities from each request:

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

`handle.emit(...)` stays available alongside the layer for things that aren't HTTP requests —
batch jobs, admin scripts, scheduled cleanups.

## Modeling your data

### Entity types

A log row carries `log_id`, `timestamp` (UTC microseconds), `actor`, `method`, `url`, `targets`, `content`,
plus any custom columns you register (text / number / json, validated on every write).
`targets` is a relation table, so one log can point at many entities.

The interesting modeling happens in the entity schemas.
You decide the field layout per type:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

If you don't need custom schemas, `default_actor` and `default_target` ship out of the box —
that's what the quick start registers.

### Field protection

Each field picks its own protection level; the default is plaintext on disk.
There is deliberately no store-wide switch —
what to protect is a per-field modeling decision.

| level | searchable? | key? | notes |
|---|---|---|---|
| `Sha256` | exact match | none | one-way hash; query probes are hashed the same way. Low-entropy values (SSNs) can be brute-forced from disk — use `Hmac` for those. |
| `Hmac` | exact match | `KeyRing::with_hmac_key` | keyed HMAC-SHA-256; worthless without the key. |
| `Rsa` | no (decrypt-scan) | RSA keypair | hybrid AES-256-GCM with RSA-OAEP key wrapping; authenticated — an in-place edit makes decryption fail. |

One scope rule to internalize early: protection covers registry **fields only**.
`entity_id`, the log's `method`/`url`/`content`, and custom columns are always plaintext,
because they're what queries filter and render on.

So model sensitive values as protected fields, give entities opaque ids (not SSNs),
and keep PII out of `content` —
a captured request body is the easiest place to leak it by accident.

### Blind indexes: searching what you encrypted

Protection limits search: hashed fields are exact-match only, RSA fields need a full decrypt-scan.
A *blind index* buys back richer matching:

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // exact match
    .search(FieldIndex::Ngram(3)),      // + substring match
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + prefix match up to 4 chars
```

At write time, while the plaintext is still in hand,
lowercased tokens are digested and stored next to the record —
the whole value for `Exact`, first `1..=n` chars for `Prefix(n)`, n-char windows for `Ngram(n)`.
Search survives restarts; the plaintext never hits disk.

The trade: token digests follow the field's own key discipline (keyed fields get keyed tokens),
so they add no brute-force surface beyond what you already declared —
but they do leak *structure*, namely which stored values share prefixes or fragments.
Declaring an index is accepting that trade for that one field,
which is why there's no global switch here either.

### Schema evolution

Redefining a type is additive only:
new fields yes, removing or changing the kind/protection/index of existing ones no.
Allowing that would silently break the "past values stay searchable" promise.

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

Every hit comes back with actor/target snapshots as they were recorded,
plus an RFC 3339 UTC timestamp.

### Match operators

Besides `exact` and `contains()` there are `prefix()` and `exact_ci()` (case-insensitive exact).
On plain fields they always work.
On protected fields, `prefix()` / `exact_ci()` need the matching `FieldIndex` declared
and then match with no false positives.
`contains()` is the subtle one:

- With an `Ngram(n)` index, probes of at least n chars match by token digests,
  case-insensitively, no plaintext involved.
  RSA candidates are then decrypted and verified (needs `StoreConfig::plaintext_cache(true)`).
  Hashed fields have no plaintext to verify against,
  so a hit means "carries all the probe's fragments" — false positives possible;
  pair with `Rsa` when hits must be exact.
- Without an index, `contains()` on a protected field requires opting into `StoreConfig::plaintext_cache(true)`,
  which holds decrypted/written values in memory (never persisted; gone after restart).
  With the cache off — the default — the query is rejected outright
  rather than silently caching plaintexts you didn't ask for.

### Snapshots and registry browsing

Queries run against a read snapshot (`handle.snapshot(&role)?`).
Taking one only clones the small in-memory registry indexes,
and the scan runs on the caller's thread —
a slow full-scan query never gets in the way of event persistence.

```rust
handle.entity_types(&role)?;                            // all type schemas
handle.list_entities(&role, "default_target", false)?;  // latest version per entity
handle.entity_history(&role, "default_target", "doc-1")?; // every version, oldest first
```

## Server mode: one log for many services

Everything above runs *embedded* — the store inside your service's process.
`quipu-server` runs the same engine as a standalone daemon behind a token-authenticated HTTP/JSON API,
so multiple services in any language can record and search audit logs centrally:

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

The store stays single-process; the daemon is that process.
Auth is deny-by-default with per-token role grants.

The server can also run *write-only*:
started without the RSA private key, it stores encrypted fields
but returns them as ciphertext for clients to decrypt locally —
a compromised server can't recover plaintext.

Configuration, the full HTTP API, and v1 limits live in the
[quipu-server README](crates/quipu-server/README.md).

## Meta-audit: who looked at the audit log

In regulated environments, reading audit data is itself an auditable event —
HIPAA expects a record of who viewed PHI, and that includes viewing it through
the audit trail. Opt in and quipu records every read and admin operation
against the store — queries, registry browsing, DLQ redrives, retention runs,
flushes, integrity verifications, token reloads — in a dedicated **access log**:

```rust
let cfg = StoreConfig::new("./audit-data")
    .access_log(true)                              // opt-in
    .access_retention(RetentionPolicy::days(90));  // independent window
```

Each record carries the actor (the bearer token's role in server mode), the
operation, a parameter summary, the result count, and a timestamp. Two things
hold by construction:

- **No self-reference loop.** Recording an access is a plain append — it never
  runs a query, so it can never spawn another access record. Reading the
  access log *is* recorded (it is an access too), but exactly once per read:
  growth is linear, never recursive.
- **Search probes stay out.** The parameter summary keeps the *shape* of a
  query (which fields, which match mode, what time range) but never the probe
  values — otherwise searching an HMAC/RSA-protected field would leak its
  plaintext into the access log and defeat the field protection.

Access records live in their own table (`root/access/`, with its own
tamper-evidence chain, covered by `verify_integrity`). That separation is
what makes the **independent retention window** possible: retention drops
whole segments per table, so access records — usually kept shorter than the
audit data they describe — age out on their own schedule without touching
the main log.

Reading it back: embedded, `handle.query_access(&admin_role, AccessQuery::default())`
(filter by actor, operation, time range); in server mode, `POST /v1/access/query`
with the `administer` grant, enabled via `store.access_log: true` /
`store.access_retention_days` in the config.

## Operational notes

- **Permissions** — role-based `Emit` / `Query` / `Administer` grants,
  in allowlist or denylist mode.
- **Retention** — `RetentionPolicy::days(90)` drops old data by deleting whole sealed segments:
  one `unlink`, no rewrites.
  Registries are kept so old history stays renderable.
- **Durability** — pick `SyncPolicy::Always` (fsync every write), `EveryN(n)`, or `OsManaged`.
- **Dead-letter queue** — events that exhaust their retries are parked on disk,
  survive restarts, and are replayed with `handle.redrive_dlq(&admin_role)`.
  Redrive is crash-safe and at-least-once;
  replayed logs keep their original occurrence time,
  and `required` custom columns aren't enforced retroactively,
  so old parked events always stay redrivable.
- **Single process only** — the store root is guarded by an OS file lock;
  a second process opening the same root fails fast instead of corrupting it.
- **Integrity audit** — `store.verify_integrity()` walks every table's hash chain
  and reports the first record modified in place or segment swapped out.
- **Format versioning** — segment files start with a magic + version byte,
  so future layout changes ship as migrations, not misreads.
- **Observability** — every write outcome is reported via `tracing`.

## Workspace layout

| crate | what it is |
|---|---|
| `quipu-core` | storage engine, typed registries, field encryption, retention, queries |
| `quipu-middleware` | event pipeline (DLQ/fallback), pre/post filters, permissions, `tower` proxy layer |
| `quipu-server` | standalone daemon: the same store behind a token-authenticated HTTP/JSON API |
| `examples/axum-demo` | runnable axum integration |

## Running the demo and tests

```sh
cargo test                 # core + middleware test suites
cargo run -p axum-demo     # then: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## License

Apache-2.0
