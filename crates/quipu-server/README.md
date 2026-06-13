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
    "plaintext_cache": false
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
  "verify": { "interval_secs": 86400 }
}
```

- `sync_policy`: `"always"`, `"os_managed"`, or `{ "every_n": N }`.
- `verify` (optional): periodic [integrity verification](#integrity-verification) —
  one pass at startup, then one per `interval_secs`. Omit to disable.
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
503 (append queue full — back off and retry), or 500.

| method & path | action | body / response |
|---|---|---|
| `GET /v1/healthz` | — | `ok` |
| `POST /v1/types` | administer | `TypeSchema` JSON → 204. Additive redefinition only. |
| `GET /v1/types` | query | `[TypeSchema]` |
| `POST /v1/columns` | administer | `CustomColumnDef` JSON → 204 |
| `POST /v1/logs` | emit | append request → **202** `{"status":"queued"}` |
| `POST /v1/logs/query` | query | `LogQuery` JSON → `[LogView]` |
| `GET /v1/entities/{type}?include_deleted=` | query | `[TargetSnapshot]` (latest versions) |
| `GET /v1/entities/{type}/{id}/history` | query | `[TargetSnapshot]` (oldest first) |
| `POST /v1/admin/flush` | administer | fsync everything queued → 204 |
| `POST /v1/admin/redrive` | administer | `{"redriven": n}` |
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

## Limits (v1, by design)

- One store, one tenant:
  tokens separate *capabilities* (emit/query/admin), not data —
  every reader sees every log.
  Per-tenant isolation would mean per-tenant store roots and is future work.
- No Rust client crate yet;
  the API above is small enough to call with any HTTP client,
  which is the point of choosing JSON over gRPC.
