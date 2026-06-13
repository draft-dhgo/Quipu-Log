# quipu-server

English | [한국어](README.ko.md)

Standalone audit-log daemon.
It wraps the embedded `quipu-core` store in `quipu-middleware`'s async pipeline
and exposes it over an HTTP/JSON API,
so multiple services — in any language — can record and search audit logs centrally
(the Elasticsearch-style deployment shape).
The embedded mode keeps working; this is a second way to run the same engine, not a replacement.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

The store stays single-process (`root/LOCK`); the daemon is that process.
Appends go through the pipeline's bounded queue + writer thread (retries, disk-backed DLQ),
queries run on point-in-time snapshots in the blocking pool,
so a slow scan never stalls ingestion.

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
- `retention_days` / `retention_max_bytes` (both optional): age window and
  byte budget for the logs + relations tables. They combine as **OR** —
  the oldest sealed segments are dropped as soon as either limit is exceeded.
- `access_log` (optional, default false): meta-audit — record every query and
  admin operation against the store in a dedicated access log, readable via
  `POST /v1/access/query`. `access_retention_days` sets its retention window
  independently of `retention_days` (omit to keep access records forever).
- `verify` (optional): periodic [integrity verification](#integrity-verification) —
  one pass at startup, then one per `interval_secs`. Omit to disable.
- `health` (optional): disk-space warning thresholds (either bound trips;
  the values shown are the defaults) and the
  [disk-full emit behaviour](#disk-full-behaviour).
- Key material is always referenced by file path, never inlined.
- Auth is deny-by-default: a role with no grants can do nothing.
  Run one token per calling service so tokens can be revoked individually.

### Token management

Store tokens **hashed**: a `sha256:<hex>` key holds the SHA-256 of the
token, so the config file itself is not a credential. Generate the hex with:

```sh
echo -n "$TOKEN" | shasum -a 256
```

Plaintext keys keep working (the server hashes them at load time and never
holds the raw token in memory afterwards), but each load logs a warning —
treat them as a migration path, not a destination.

A token's value is either a bare role name or
`{"role": ..., "expires": <unix epoch seconds>}`
(`date -d '+90 days' +%s` on Linux, `date -v+90d +%s` on macOS).
At or past `expires` the token is rejected exactly like an unknown one:
a plain 401, no hint that it ever existed.

**Hot reload.** Send `SIGHUP` to re-read the config file and swap the
`auth` section — tokens, grants, and `max_concurrent_queries` — without a
restart or dropped connections:

```sh
kill -HUP "$(pgrep -f quipu-server)"
```

Each reload logs how many tokens were added and removed, so the server log
doubles as the issue/revoke audit trail (token material itself is never
logged). A reload that fails — unreadable file, parse error, malformed
`sha256:` key — keeps the previous auth config in force and logs an error.
The other sections (`listen`, `store`, `keys`) still require a restart.

**Per-token query cap.** Queries are full scans, so one token must not be
able to monopolise the CPU: `auth.max_concurrent_queries` caps how many
queries each token may have running at once (omit it for no cap). A token
at its cap gets **429** on further queries — retry once the running ones
finish. Appends are unaffected.

### Key boundary

The server only needs the **HMAC key** (write + equality-search protected fields)
and the **RSA public key** (write encrypted fields).

Leave `private_key_pem_file` unset to run the server write-only:
queries still work, but RSA-protected values come back as ciphertext
(`{"Rsa": {wrapped_key, nonce, ciphertext}}`)
for the querying client to decrypt locally with `KeyRing::decrypt`.
That keeps plaintext recovery out of the server's blast radius.

Configuring the private key (plus `plaintext_cache: true`)
enables server-side `contains` search on RSA-protected fields,
at the cost of the server being able to read them.

### Key rotation

The single-file fields above load as **key version 1**. To rotate, switch to
the versioned lists — the highest version is active (protects new writes),
lower ones stay for reading old records:

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

After a key compromise, follow up with the offline re-key pass (server
stopped; it re-wraps RSA-protected values so the old private key can be
destroyed):

```sh
quipu-server rekey /etc/quipu/config.json
```

The full procedure — what re-key can and cannot fix, and why it stays
distinguishable from tampering — is in the
[top-level README](../../README.md#key-rotation).

## TLS

Add a `tls` section and the server terminates TLS itself (rustls):

```json
"tls": {
  "cert_pem_file": "/etc/quipu/tls/cert.pem",
  "key_pem_file": "/etc/quipu/tls/key.pem"
}
```

As with `keys`, the certificate and private key are referenced by file path,
never inlined in the config.

Why direct termination is built in
instead of being documented away to a reverse proxy:
every request carries a bearer token and audit payloads (possibly PII),
so the transport leg sits inside this server's threat model.
Delegating it to a proxy pushes the trust boundary outside the project,
and a standalone deployment could no longer keep its security promise on its own.

Running behind a TLS-terminating proxy or a service mesh still works:
omit the `tls` section and the server speaks plain HTTP as before.

For local testing, generate a self-signed certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout key.pem -out cert.pem
```

## HTTP API

All endpoints except `/v1/healthz` require `Authorization: Bearer <token>`.
Errors are `{"error": "<message>"}` with 401 (missing/unknown/expired token),
403 (role lacks the action), 400 (schema/crypto misuse), 404,
409 (a verification is already running — retry later),
429 (token at its concurrent-query cap — retry when a query finishes),
503 (append queue full — back off and retry),
507 (disk full with `reject_emit_when_disk_full` on — back off longer), or 500.

| method & path | action | body / response |
|---|---|---|
| `GET /v1/healthz` | — | `{"status": "ok"/"degraded"/"unhealthy", "reasons": [...]}` — see [Health](#health) |
| `GET /metrics` | administer | Prometheus text exposition — see [Metrics](#metrics) |
| `POST /v1/types` | administer | `TypeSchema` JSON → 204. Additive redefinition only. |
| `GET /v1/types` | query | `[TypeSchema]` |
| `POST /v1/columns` | administer | `CustomColumnDef` JSON → 204 |
| `POST /v1/logs` | emit | append request → **202** `{"status":"queued"}` |
| `POST /v1/logs/query` | query | `LogQuery` JSON → `{"logs": [LogView], "next_cursor"?, "segments_scanned"}` |
| `POST /v1/logs/count` | query | `LogQuery` JSON → `{"count": n}` (no rendering/decryption) |
| `GET /v1/entities/{type}?include_deleted=` | query | `[TargetSnapshot]` (latest versions) |
| `GET /v1/entities/{type}/{id}/history` | query | `[TargetSnapshot]` (oldest first) |
| `POST /v1/access/query` | administer | `AccessQuery` JSON (`from_micros`/`to_micros`/`actor`/`operation`/`limit`, all optional) → `[AccessRecord]`. Meta-audit: who queried/administered the store. Needs `store.access_log: true` (400 otherwise). Each read is itself recorded, exactly once. |
| `POST /v1/admin/flush` | administer | fsync everything queued → 204 |
| `POST /v1/admin/redrive` | administer | `{"redriven": n, "requeued": n, "quarantined_entries": n, "quarantined_segments": n}` — corrupt DLQ material is moved to `<dlq>.quarantine/` instead of failing the redrive |
| `POST /v1/admin/retention` | administer | `{"segments_dropped": n}` |
| `GET /v1/admin/dlq` | administer | `{"parked": n}` |
| `POST /v1/admin/verify` | administer | verify report (below); **409** while another verification runs |

A 202 means *queued*, not durable —
durability is the pipeline's job (retries, then the DLQ; nothing is silently dropped).
An event that fails validation asynchronously (e.g. undefined actor type) parks in the DLQ;
watch `GET /v1/admin/dlq`.

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

- `occurred_at` (UTC micros) is optional and defaults to server "now";
  set it if you queue/retry on the client
  so the log records when the action actually happened.
- Values are tagged: `{"Text": "..."}`, `{"Number": 1.5}`, or `{"Json": "<json as a string>"}`
  (string-wrapped because the disk format is not self-describing).
  `content` takes `Text`/`Json` the same way.

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

All set conditions are AND-ed; everything is optional (`{}` returns everything up to `limit`).
`mode` is `"exact"` (default), `"exact_ci"`, `"prefix"`, or `"contains"`;
`include_past` defaults to `true` (a renamed entity is still found by its old name).
Hits are `LogView` rows: the log plus actor/target snapshots exactly as recorded.

The response is one **page**:

```json
{
  "logs": [ ... ],
  "next_cursor": "AQEDAAAAAAAAACkAAAAAAAAA",
  "segments_scanned": 2
}
```

- `order` is `"desc"` (default — newest first, so `limit` means "the latest N")
  or `"asc"`. With a time range (`from_micros`/`to_micros`), segment files
  entirely outside the window are never even opened.
- `next_cursor` is present when more matches remain. Send it back verbatim as
  `"cursor"` with an otherwise **identical** query to get the next page; it is
  an opaque token, not something to parse. The last page has no `next_cursor`.
- A cursor stays valid while you paginate: records appended after a
  newest-first listing started do not shift, duplicate, or punch holes in the
  remaining pages (they appear in the *next* fresh query).
- A cursor that does not decode, or was issued under the opposite `order`,
  gets a 400.

To size a result set without paying for rendering or decryption, use
`POST /v1/logs/count` with the same `LogQuery` body (`limit`, `cursor` and
`order` are ignored):

```sh
curl -s -X POST localhost:7700/v1/logs/count \
  -H 'Authorization: Bearer aud1tor-t0ken' -H 'Content-Type: application/json' \
  -d '{ "method": "DELETE", "from_micros": 1780000000000000 }'
# {"count": 1843}
```

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

Same rules as embedded `define_type`: redefinition is additive only.

## Integrity verification

Every table is a hash chain (`sha256(previous chain value || payload)`,
seeded across segment boundaries), so in-place edits and removed or
replaced segments are detectable after the fact. The embedded API has
`AuditStore::verify_integrity()`; the server exposes the same check two ways:

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

A found chain break is a *successful* verification: still 200, with
`"ok": false` and the break described in `problems` (verification stops at
the first break, so it lists at most one). Only "could not verify at all"
is an error status.

**Periodic** — add a `verify` section to the config:

```json
"verify": { "interval_secs": 86400 }
```

One pass runs at startup, then one per interval. A pass that finds a break —
or cannot run — logs at `error` level; point your alerting at that line.
Omit the section to disable (the endpoint works either way).

Two things to know before pointing a cron at it:

- At most one verification runs at a time, shared between the endpoint and
  the periodic task: the endpoint answers **409** while one is running, the
  periodic task skips its tick with a warning.
- Verification re-reads every segment **on the writer thread** (the chains
  live under the store's single-writer lock). While it runs, appends queue
  up in the bounded pipeline queue instead of being persisted — fine for
  typical stores, but on a very large store under heavy write load, schedule
  it off-peak or expect some 503s on `POST /v1/logs` during the pass.

## Health

`GET /v1/healthz` (no token) answers
`{"status": "ok"|"degraded"|"unhealthy", "reasons": [...]}`:

- **`unhealthy`** (HTTP **503**) — events are *not* being persisted:
  the writer thread is dead, the disk-full latch is set,
  or a probe write into the store root just failed.
- **`degraded`** (HTTP **200**) — writes still work, but free disk space is
  below the `health` thresholds. 200 on purpose: a load balancer must not
  eject an instance that is still persisting events; the body carries the
  warning for monitoring to alert on.
- **`ok`** (HTTP **200**).

Each check runs live per request: writer liveness and the disk-full latch
from the pipeline, plus an actual create-write-fsync-delete probe in the
store root and a fresh free-space measurement.

> Compatibility: before v0.2 this endpoint returned plain-text `ok`
> unconditionally. Monitors matching on the body must switch to the status
> code or the JSON `status` field.

## Metrics

`GET /metrics` renders Prometheus text format (v0.0.4). It sits behind a
bearer token with `administer`, like the rest of the operational surface —
give Prometheus its own token:

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

Alerting starter pack: page on `quipu_writer_alive == 0`, `quipu_disk_full
== 1` or `rate(quipu_events_lost_total[5m]) > 0`; warn on `quipu_dlq_entries
> 0` for more than a few minutes, `quipu_disk_low == 1`, or a growing
`quipu_queue_depth`.

## Disk-full behaviour

What happens when the volume under the store root fills up is defined, not
emergent:

1. **Early warning.** Every housekeeping interval (30s) the pipeline
   measures free space. Crossing below the `health` thresholds logs a
   `warn`, notifies the fallback hook once, flips `quipu_disk_low` to 1 and
   turns `/v1/healthz` `degraded`. This is the moment to act — grow the
   volume, lower `retention_max_bytes`, or run `POST /v1/admin/retention`.
2. **ENOSPC.** A write that fails with "no space left on device" skips the
   retry/backoff loop entirely (the condition is persistent; rewriting the
   same bytes cannot succeed) and goes straight to the DLQ — which usually
   sits on the same full disk and also fails, so the event reaches the
   fallback hook and `quipu_events_lost_total`. The disk-full latch is set:
   `quipu_disk_full` reads 1 and `/v1/healthz` answers 503.
3. **Fast reject (opt-in).** With `health.reject_emit_when_disk_full` set,
   `POST /v1/logs` answers **507** immediately while the latch is set,
   instead of queueing events that are bound for the fallback hook anyway —
   callers get backpressure they can act on.
4. **Recovery is automatic.** The latch clears as soon as a write succeeds
   again, or when housekeeping measures free space back above the warning
   thresholds. No restart, no manual reset.

The matching *prevention* knob is `retention_max_bytes`: give the store a
byte budget below the volume size and retention keeps it there by dropping
the oldest sealed segments — same whole-segment unlink as `retention_days`,
so integrity verification still passes afterwards.

## Limits (v1, by design)

- One store, one tenant:
  tokens separate *capabilities* (emit/query/admin), not data —
  every reader sees every log.
  Per-tenant isolation would mean per-tenant store roots and is future work.
- No Rust client crate yet;
  the API above is small enough to call with any HTTP client,
  which is the point of choosing JSON over gRPC.
