# quipu-server

English | [한국어](README.ko.md)

Standalone audit-log daemon. It wraps the embedded `quipu-core` store in `quipu-middleware`'s async pipeline and exposes it over an HTTP/JSON API, so multiple services — in any language — can record and search audit logs in one place (the Elasticsearch-style deployment shape). Embedded mode keeps working; this is a second way to run the same engine, not a replacement.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

The store stays single-process (`root/LOCK`); the daemon is that process. Appends go through the pipeline's bounded queue and writer thread (retries, disk-backed DLQ). Queries run on point-in-time snapshots in the blocking pool, so a slow scan never stalls ingestion.

## Running

```sh
cargo run -p quipu-server -- config.json
```

`config.json`:

```json
{
  "listen": "127.0.0.1:7700",
  "store": {
    "root": "/var/lib/quipu",
    "sync_policy": { "every_n": 64 },
    "retention_days": 365,
    "retention_max_bytes": 53687091200,
    "plaintext_cache": false,
    "access_log": true,
    "access_retention_days": 90
  },
  "keys": {
    "hmac_key_file": "/etc/quipu/hmac.key",
    "public_key_pem_file": "/etc/quipu/rsa-pub.pem"
  },
  "auth": {
    "tokens": {
      "sha256:4d41854aa8c3af67915fd2808c9060f711ce4ca8f85c77120b7f393b2685b817": "writer",
      "sha256:00fd2eabbe5cdebba9140e6b6516695e313b825400d79812013ace3c5101a073": {
        "role": "reader",
        "expires": 1790000000
      },
      "adm1n-t0ken": "admin"
    },
    "grants": {
      "writer": ["emit"],
      "reader": ["query"],
      "admin": ["emit", "query", "administer"]
    },
    "max_concurrent_queries": 2
  },
  "verify": { "interval_secs": 86400 },
  "health": {
    "min_free_bytes": 1073741824,
    "min_free_ratio": 0.10,
    "reject_emit_when_disk_full": false
  }
}
```

- `sync_policy`: `"always"`, `"os_managed"`, or `{ "every_n": N }`.
- `retention_days` / `retention_max_bytes` (both optional): age window and byte budget for the logs + relations tables. They combine as **OR** — the oldest sealed segments are dropped as soon as either limit is exceeded.
- `access_log` (optional, default false): meta-audit. Records every query and admin operation against the store in a dedicated access log, readable via `POST /v1/access/query`. `access_retention_days` sets its retention window independently of `retention_days` (omit to keep access records forever).
- `verify` (optional): periodic [integrity verification](#integrity-verification) — one pass at startup, then one per `interval_secs`. Omit to disable.
- `health` (optional): disk-space warning thresholds (either bound trips; the values shown are the defaults) and the [disk-full emit behaviour](#disk-full-behaviour).
- Key material is always referenced by file path, never inlined.
- Auth is deny-by-default: a role with no grants can do nothing. Run one token per calling service so tokens can be revoked individually.

### Token management

Store tokens **hashed**. A `sha256:<hex>` key holds the SHA-256 of the token, so the config file itself isn't a credential. Generate the hex with:

```sh
echo -n "$TOKEN" | shasum -a 256
```

Plaintext keys keep working — the server hashes them at load time and never holds the raw token in memory afterward — but each load logs a warning. Treat them as a migration path, not a destination.

A token's value is either a bare role name or `{"role": ..., "expires": <unix epoch seconds>}` (`date -d '+90 days' +%s` on Linux, `date -v+90d +%s` on macOS). At or past `expires`, the token is rejected exactly like an unknown one: a plain 401, no hint that it ever existed.

**Hot reload.** Send `SIGHUP` to re-read the config and swap the `auth` section — tokens, grants, and `max_concurrent_queries` — with no restart and no dropped connections:

```sh
kill -HUP "$(pgrep -f quipu-server)"
```

Each reload logs how many tokens were added and removed, so the server log doubles as the issue/revoke audit trail (token material itself is never logged). A reload that fails — unreadable file, parse error, malformed `sha256:` key — keeps the previous auth config in force and logs an error. The other sections (`listen`, `store`, `keys`) still require a restart.

**Per-token query cap.** Queries are full scans, so one token must not be able to monopolize the CPU. `auth.max_concurrent_queries` caps how many queries each token may run at once (omit it for no cap). A token at its cap gets **429** on further queries — retry once the running ones finish. Appends are unaffected.

### Key boundary

The server only needs the **HMAC key** (to write and equality-search protected fields) and the **RSA public key** (to write encrypted fields).

Leave `private_key_pem_file` unset to run write-only. Queries still work, but RSA-protected values come back as ciphertext (`{"Rsa": {wrapped_key, nonce, ciphertext}}`) for the querying client to decrypt locally with `KeyRing::decrypt`. Plaintext recovery stays out of the server's blast radius.

Configuring the private key (plus `plaintext_cache: true`) enables server-side `contains` search on RSA-protected fields — at the cost of the server being able to read them.

### Key rotation

The single-file fields above load as **key version 1**. To rotate, switch to the versioned lists. The highest version is active (protects new writes); lower ones stay for reading old records:

```json
"keys": {
  "hmac_keys": [
    { "version": 1, "file": "/etc/quipu/hmac-v1.key" },
    { "version": 2, "file": "/etc/quipu/hmac-v2.key" }
  ],
  "rsa_keys": [
    { "version": 1, "public_key_pem_file": "/etc/quipu/rsa-v1-pub.pem" },
    { "version": 2, "public_key_pem_file": "/etc/quipu/rsa-v2-pub.pem" }
  ]
}
```

Routine rotation (no compromise) ends there: old records keep working, new writes use the highest version. After a key **compromise**, run the offline re-key pass so the leaked RSA private key can no longer read the data at rest:

1. Stop the service and back up the store directory.
2. Add the new key versions to the config, keeping the old ones.
3. Run the re-key. It unwraps every RSA-protected value with the old private key, re-wraps it under the new public key, and re-digests RSA fields' blind-index tokens under the new HMAC key:

   ```sh
   quipu-server rekey /etc/quipu/config.json   # or AuditStore::rekey() when embedded
   ```
4. Check the printed summary, then **destroy the old RSA private key** — it can no longer decrypt anything in the store. Keep old HMAC keys and old public keys.
5. Restart.

Re-key rewrites registry tables, which produces new hash chains — exactly what tampering looks like. So the pass appends a **signed re-key event** to the chained meta table, recording each registry's old-head → new-head transition. `verify_integrity()` checks every re-key signature and that each chain still contains the head the latest event signed, so an audited re-key stays distinguishable from a silent rewrite.

Two limits. HMAC fields are one-way with no plaintext on disk, so they **can't** be re-keyed: keep their old HMAC keys for search, and know that a leaked HMAC key has permanently exposed the digests written under it. And re-key covers the registries, not log rows — `method`/`url`/`content` are plaintext by design and have no keys to rotate.

## TLS

Add a `tls` section and the server terminates TLS itself (rustls):

```json
"tls": {
  "cert_pem_file": "/etc/quipu/tls/cert.pem",
  "key_pem_file": "/etc/quipu/tls/key.pem"
}
```

As with `keys`, the certificate and private key are referenced by file path, never inlined.

Why TLS termination is built in rather than left to a reverse proxy: every request carries a bearer token and audit payloads, possibly PII. The transport leg sits inside this server's threat model. Hand it to a proxy and the trust boundary moves outside the project — a standalone deployment could no longer keep its security promise on its own.

Running behind a TLS-terminating proxy or a service mesh still works: omit the `tls` section and the server speaks plain HTTP as before.

For local testing, generate a self-signed certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout key.pem -out cert.pem
```

## HTTP API

All endpoints except `/v1/healthz` require `Authorization: Bearer <token>`. Errors are `{"error": "<message>"}` with 401 (missing/unknown/expired token), 403 (role lacks the action), 400 (schema/crypto misuse), 404, 409 (a verification is already running — retry later), 429 (token at its concurrent-query cap — retry when a query finishes), 503 (append queue full — back off and retry), 507 (disk full with `reject_emit_when_disk_full` on — back off longer), or 500.

The full machine-readable contract is served at **`GET /v1/openapi.json`** (OpenAPI 3.1, unauthenticated — it's an interface description, not data). Point a code generator or Swagger UI at it; the table below is the human summary.

| method & path | action | body / response |
|---|---|---|
| `GET /v1/healthz` | — | `{"status": "ok"/"degraded"/"unhealthy", "reasons": [...]}` — see [Health](#health) |
| `GET /metrics` | administer | Prometheus text exposition — see [Metrics](#metrics) |
| `GET /v1/openapi.json` | — | this API's OpenAPI 3.1 document |
| `POST /v1/types` | administer | `TypeSchema` JSON → 204. Additive redefinition only. |
| `GET /v1/types` | query | `[TypeSchema]` |
| `POST /v1/columns` | administer | `CustomColumnDef` JSON → 204 |
| `POST /v1/logs` | emit | append request → **202** `{"status":"queued"}` |
| `POST /v1/logs/query` | query | `LogQuery` JSON → `{"logs": [LogView], "next_cursor"?, "segments_scanned"}` |
| `POST /v1/logs/count` | query | `LogQuery` JSON → `{"count": n}` (no rendering/decryption) |
| `POST /v1/logs/export` | query | `LogQuery` JSON → `application/x-ndjson` (one `LogView` per line) |
| `GET /v1/entities/{type}?include_deleted=` | query | `[TargetSnapshot]` (latest versions) |
| `GET /v1/entities/{type}/{id}/history` | query | `[TargetSnapshot]` (oldest first) |
| `POST /v1/access/query` | administer | `AccessQuery` JSON (`from_micros`/`to_micros`/`actor`/`operation`/`limit`, all optional) → `[AccessRecord]`. Meta-audit: who queried/administered the store. Needs `store.access_log: true` (400 otherwise). Each read is itself recorded, exactly once. |
| `POST /v1/admin/flush` | administer | fsync everything queued → 204 |
| `POST /v1/admin/redrive` | administer | `{"redriven": n, "requeued": n, "quarantined_entries": n, "quarantined_segments": n}` — corrupt DLQ material is moved to `<dlq>.quarantine/` instead of failing the redrive |
| `POST /v1/admin/retention` | administer | `{"segments_dropped": n}` |
| `GET /v1/admin/dlq` | administer | `{"parked": n}` |
| `POST /v1/admin/verify` | administer | verify report (below); **409** while another verification runs |

A 202 means *queued*, not durable — durability is the pipeline's job (retries, then the DLQ; nothing is silently dropped). An event that fails validation asynchronously (e.g. an undefined actor type) parks in the DLQ; watch `GET /v1/admin/dlq`.

### Appending

```sh
curl -s -X POST localhost:7700/v1/logs \
  -H 'Authorization: Bearer s3rv1ce-a-t0ken' -H 'Content-Type: application/json' -d '{
  "actor_type": "user",
  "actor": { "entity_id": "alice", "fields": { "name": { "Text": "Alice" } } },
  "method": "POST",
  "url": "/api/documents/42",
  "content": { "Json": "{\"action\":\"share\"}" },
  "targets": [
    { "entity_type": "document",
      "input": { "entity_id": "42", "fields": { "title": { "Text": "Q3 plan" } } } }
  ],
  "custom": { "request_id": { "Text": "r-123" } }
}'
```

- `occurred_at` (UTC micros) is optional and defaults to server "now". Set it if you queue or retry on the client, so the log records when the action actually happened.
- Values are tagged: `{"Text": "..."}`, `{"Number": 1.5}`, or `{"Json": "<json as a string>"}` (string-wrapped because the disk format isn't self-describing). `content` takes `Text`/`Json` the same way.

### Querying

```sh
curl -s -X POST localhost:7700/v1/logs/query \
  -H 'Authorization: Bearer aud1tor-t0ken' -H 'Content-Type: application/json' -d '{
  "from_micros": 1780000000000000,
  "method": "POST",
  "targets": [
    { "entity_type": "document", "field": "title",
      "value": { "Text": "q3" }, "mode": "prefix" }
  ],
  "limit": 100
}'
```

All set conditions are AND-ed; everything is optional (`{}` returns everything up to `limit`). `mode` is `"exact"` (default), `"exact_ci"`, `"prefix"`, or `"contains"`. `include_past` defaults to `true` (a renamed entity is still found by its old name). Hits are `LogView` rows: the log plus actor/target snapshots exactly as recorded.

The response is one **page**:

```json
{
  "logs": [ ... ],
  "next_cursor": "AQEDAAAAAAAAACkAAAAAAAAA",
  "segments_scanned": 2
}
```

- `order` is `"desc"` (default — newest first, so `limit` means "the latest N") or `"asc"`. With a time range (`from_micros`/`to_micros`), segment files entirely outside the window are never opened.
- `next_cursor` is present when more matches remain. Send it back verbatim as `"cursor"` with an otherwise **identical** query to get the next page. It's an opaque token, not something to parse. The last page has no `next_cursor`.
- A cursor stays valid while you paginate: records appended after a newest-first listing started don't shift, duplicate, or punch holes in the remaining pages (they appear in the *next* fresh query).
- A cursor that doesn't decode, or was issued under the opposite `order`, gets a 400.

To size a result set without paying for rendering or decryption, use `POST /v1/logs/count` with the same `LogQuery` body (`limit`, `cursor`, and `order` are ignored):

```sh
curl -s -X POST localhost:7700/v1/logs/count \
  -H 'Authorization: Bearer aud1tor-t0ken' -H 'Content-Type: application/json' \
  -d '{ "method": "DELETE", "from_micros": 1780000000000000 }'
# {"count": 1843}
```

### Exporting (auditor handoff, SIEM ingest)

`POST /v1/logs/export` takes the **same `LogQuery` body** as `/v1/logs/query` but answers with `application/x-ndjson` — one `LogView` JSON object per line — the format auditors and log pipelines expect for bulk handoff:

```sh
curl -s -X POST localhost:7700/v1/logs/export \
  -H 'Authorization: Bearer aud1tor-t0ken' -H 'Content-Type: application/json' \
  -d '{ "from_micros": 1780000000000000 }' > audit-export.ndjson
```

Same permission (`query`) and per-token concurrency cap as a query; only the response framing differs. Field protection obeys the same key boundary: a server without the RSA private key exports protected fields as ciphertext for the key-holder to decrypt downstream. Scope the dump with `from_micros`/`to_micros` — it's a full scan, so an unbounded export of a large store is the one query most worth bounding.

### Defining a type

```sh
curl -s -X POST localhost:7700/v1/types \
  -H 'Authorization: Bearer adm1n-t0ken' -H 'Content-Type: application/json' -d '{
  "type_name": "document",
  "fields": [
    { "name": "title", "kind": "Text", "protection": "None",
      "indexed": true, "required": true, "search": { "Prefix": 8 } },
    { "name": "owner_ssn", "kind": "Text", "protection": "Hmac",
      "indexed": true, "required": false, "search": "None" }
  ]
}'
```

Same rule as embedded `define_type`: redefinition is additive only.

## Integrity verification

Every table is a hash chain (`sha256(previous chain value || payload)`, seeded across segment boundaries), so in-place edits and removed or replaced segments are detectable after the fact. The embedded API has `AuditStore::verify_integrity()`; the server exposes the same check two ways.

**On demand** — `POST /v1/admin/verify` (administer):

```sh
curl -s -X POST localhost:7700/v1/admin/verify \
  -H 'Authorization: Bearer adm1n-t0ken'
```

```json
{
  "ok": true,
  "segments_checked": 7,
  "log_records": 1843,
  "problems": []
}
```

A found chain break is a *successful* verification: still 200, with `"ok": false` and the break described in `problems` (verification stops at the first break, so it lists at most one). Only "could not verify at all" is an error status.

**Periodic** — add a `verify` section to the config:

```json
"verify": { "interval_secs": 86400 }
```

One pass runs at startup, then one per interval. A pass that finds a break — or can't run — logs at `error` level; point your alerting at that line. Omit the section to disable (the endpoint works either way).

Two things to know before pointing a cron at it:

- At most one verification runs at a time, shared between the endpoint and the periodic task. The endpoint answers **409** while one is running; the periodic task skips its tick with a warning.
- Verification re-reads every segment **on the writer thread** (the chains live under the store's single-writer lock). While it runs, appends queue up in the bounded pipeline queue instead of being persisted. That's fine for typical stores, but on a very large store under heavy write load, schedule it off-peak or expect some 503s on `POST /v1/logs` during the pass.

## Health

`GET /v1/healthz` (no token) answers `{"status": "ok"|"degraded"|"unhealthy", "reasons": [...]}`:

- **`unhealthy`** (HTTP **503**) — events are *not* being persisted: the writer thread is dead, the disk-full latch is set, or a probe write into the store root just failed.
- **`degraded`** (HTTP **200**) — writes still work, but free disk space is below the `health` thresholds. 200 on purpose: a load balancer must not eject an instance that's still persisting events. The body carries the warning for monitoring to alert on.
- **`ok`** (HTTP **200**).

Each check runs live per request: writer liveness and the disk-full latch from the pipeline, plus an actual create-write-fsync-delete probe in the store root and a fresh free-space measurement.

> Compatibility: before v0.2 this endpoint returned plain-text `ok` unconditionally. Monitors matching on the body must switch to the status code or the JSON `status` field.

## Metrics

`GET /metrics` renders Prometheus text format (v0.0.4). It sits behind a bearer token with `administer`, like the rest of the operational surface — give Prometheus its own token:

```yaml
scrape_configs:
  - job_name: quipu
    authorization: { credentials: <token> }
    static_configs: [{ targets: ["quipu-host:7700"] }]
```

| metric | type | meaning |
|---|---|---|
| `quipu_queue_depth` | gauge | events enqueued, not yet picked up by the writer |
| `quipu_dlq_entries` | gauge | events parked in the dead-letter queue |
| `quipu_writes_ok_total` | counter | events durably appended |
| `quipu_write_retries_total` | counter | failed write attempts that were retried |
| `quipu_writes_parked_total` | counter | events that exhausted retries (or hit disk-full) → DLQ |
| `quipu_events_lost_total` | counter | store *and* DLQ both failed; fallback hook only |
| `quipu_emit_rejected_total{reason}` | counter | emits bounced at the caller: `queue_full` / `disk_full` |
| `quipu_write_latency_seconds` | histogram | wall time to durably persist one event (incl. retries) |
| `quipu_store_bytes` | gauge | bytes on disk under the store root (all tables + DLQ) |
| `quipu_disk_free_bytes` / `quipu_disk_total_bytes` | gauge | filesystem holding the store root |
| `quipu_writer_alive` | gauge | 1 while the writer thread runs |
| `quipu_disk_full` | gauge | 1 while the ENOSPC latch is set |
| `quipu_disk_low` | gauge | 1 while free space is below the warning thresholds |
| `quipu_verify_runs_total` | counter | completed integrity verification passes |

Alerting starter pack: page on `quipu_writer_alive == 0`, `quipu_disk_full == 1`, or `rate(quipu_events_lost_total[5m]) > 0`. Warn on `quipu_dlq_entries > 0` for more than a few minutes, `quipu_disk_low == 1`, or a growing `quipu_queue_depth`.

## Disk-full behaviour

What happens when the volume under the store root fills up is defined, not left to chance:

1. **Early warning.** Every housekeeping interval (30s) the pipeline measures free space. Crossing below the `health` thresholds logs a `warn`, notifies the fallback hook once, flips `quipu_disk_low` to 1, and turns `/v1/healthz` `degraded`. This is the moment to act: grow the volume, lower `retention_max_bytes`, or run `POST /v1/admin/retention`.
2. **ENOSPC.** A write that fails with "no space left on device" skips the retry/backoff loop entirely — the condition is persistent, so rewriting the same bytes can't succeed — and goes straight to the DLQ. The DLQ usually sits on the same full disk and also fails, so the event reaches the fallback hook and `quipu_events_lost_total`. The disk-full latch is set: `quipu_disk_full` reads 1 and `/v1/healthz` answers 503.
3. **Fast reject (opt-in).** With `health.reject_emit_when_disk_full` set, `POST /v1/logs` answers **507** immediately while the latch is set, instead of queueing events that are bound for the fallback hook anyway. Callers get backpressure they can act on.
4. **Recovery is automatic.** The latch clears as soon as a write succeeds again, or when housekeeping measures free space back above the warning thresholds. No restart, no manual reset.

The matching *prevention* knob is `retention_max_bytes`: give the store a byte budget below the volume size and retention holds it there by dropping the oldest sealed segments — the same whole-segment unlink as `retention_days`, so integrity verification still passes afterward.

## Availability and recovery

The daemon is a single process by design (see the [root README's scope section](../../README.md#why-no-distributed-storage)): one writer is what keeps the store to one file lock and one unbroken hash chain. That makes the daemon a single point of availability — while it's down, callers' audit trails stall — so the project solves availability at the *client*, not by replicating the chain.

### Idempotent appends

`POST /v1/logs` accepts an `Idempotency-Key` header (any opaque 1–128 char visible-ASCII string; a UUIDv4 is the recommended shape):

```sh
curl -s -X POST localhost:7700/v1/logs \
  -H 'Authorization: Bearer s3rv1ce-a-t0ken' \
  -H 'Idempotency-Key: 6f1e...c2' \
  -H 'Content-Type: application/json' -d '{ ... }'
```

The server remembers recently accepted keys (config `"idempotency": { "window": 65536 }`; in memory, forgotten on restart) and answers a repeat with `202 {"status":"duplicate"}` instead of recording a second event. This is what makes a client safe to retry a request it couldn't confirm — a timeout can't tell "queued" from "lost".

The window is in memory by design. A retransmission that straddles a server restart can record twice, but both copies carry the same client-set `occurred_at`, so the duplicate is detectable after the fact. That restart case is the only duplicate path.

### Cold-standby failover

Recover from a failed or stopped node by cold standby, not live failover. There's no second writer to fail over *to* — that's the point of the single-chain design.

1. **Quiesce the active node** if it's still up: send `SIGINT`/`SIGTERM` for a clean shutdown (final fsync), or call `POST /v1/admin/flush` to push the active segment and registry tail to disk. Sealed segments are already immutable and safe to copy anytime; this step only settles the *active* tail.
2. **Copy the store root** to the standby host (`rsync`, snapshot, or restore from backup — see the root README's export/backup notes). Because sealed segments never change, an incremental copy only moves the active tail.
3. **Start the daemon on the standby** against the copied root. On open it takes the `LOCK` file, truncates any torn tail left by an unclean stop (CRC-framed, so a half-written record is dropped, never misread), and is writable again.
4. **Repoint clients** (DNS / load balancer) at the standby. Clients running `quipu-client` held their events in the local spool through the gap and replay them on the next `drain_spool`; the idempotency keys make a replay of anything the old node already accepted a no-op.

Restart time is bounded by the size of the **active** segment plus the registry replay, not the whole store — sealed segments are never rescanned on open. Keeping `max_segment_bytes` modest keeps that tail, and therefore failover, fast.

### SIEM forwarding

Mirror every durably-written event to a syslog collector (RFC 5424 over UDP) by adding a `sink` section:

```json
"sink": { "syslog_udp": "10.0.0.5:514", "app_name": "quipu-server", "queue_capacity": 16384 }
```

Each accepted event becomes one syslog line whose message is a compact JSON summary: log id, actor, method, url, target ids, custom-column keys. The event **`content` is not forwarded** — it can be large or hold protected values, and the store is the system of record, so the SIEM gets the audit-trail skeleton.

The mirror is **best-effort and never back-pressures writes**: a dedicated thread owns the socket, the writer thread only does a non-blocking enqueue, and a full backlog drops lines (counted, logged sparsely) rather than stalling persistence. It fires on success only — a DLQ-parked event isn't mirrored.

Syslog is the one sink the daemon ships (no extra dependency). A webhook / Kafka / other sink is the same shape — a `quipu_middleware::SinkFn` closure — for embedded users who run the pipeline directly.

## Limits (v1, by design)

- One store, one tenant: tokens separate *capabilities* (emit/query/admin), not data — every reader sees every log. Per-tenant isolation would mean per-tenant store roots, and is future work.
- The reference client ([`quipu-client`](../quipu-client/README.md)) carries the retransmission/spool protocol but no transport. The API is small enough to call from any HTTP client, which is why it's JSON and not gRPC.
