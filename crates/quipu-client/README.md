# quipu-client

English | [한국어](README.ko.md)

Reference client for [`quipu-server`](../quipu-server/README.md). It's the protocol a calling service uses to record audit events reliably against a **single-node** server — without losing records when that node is briefly unreachable.

## Why a client crate at all

`quipu-server` is one process by design. A file lock keeps its hash-chained store to a single writer, which is what makes the tamper-evidence simple to reason about (see the [root README's scope section](../../README.md#why-no-distributed-storage)).

The cost is a single point of availability. While the daemon is down or its write queue is full, a naïve caller's audit trail just stops. For audit logs, that's a compliance hole, not a transient glitch.

Replicating the chain across nodes would complicate the proof. So the project moves that burden to the sender, where it's cheap and local. This crate is the reference implementation of the sender side.

## What it gives you

- **Idempotent retransmission** — each event carries a stable `Idempotency-Key`, reused across every retry. Resending a POST the server already accepted is recognized and dropped, not double-recorded.
- **Exponential backoff with full jitter** — transient failures retry on a bounded, randomized schedule. A fleet reconnecting after an outage won't stampede the recovering daemon.
- **Opt-in local disk spool** — when retries are exhausted, the event is appended (and fsynced) to a local file instead of dropped, then replayed once the server is back. That turns "the daemon was down" from *records lost* into *records arrived late*. Since the server keeps each event's client-set `occurred_at`, the lateness never shows in the final log. The spool is CRC-framed like the store's segments, so a crash-torn tail is detected and truncated on the next open.

## No HTTP dependency

The crate carries no HTTP client. You adapt whatever you already use (`reqwest`, `ureq`, a hand-rolled socket) through the one-method `Transport` trait. Its only job is to turn one POST into a `SendOutcome`:

| HTTP result | `SendOutcome` |
|---|---|
| `202 {"status":"queued"}` | `Accepted` |
| `202 {"status":"duplicate"}` | `Duplicate` (success — the key did its job) |
| connect/timeout/reset, `408`/`429`/`502`/`503`/`504` | `Retry` |
| `400`/`401`/`403`/`404` | `Fatal` (don't retry; spooling would just replay a rejection) |

That classification is the whole contract — the retry loop knows only those four outcomes. The transport also owns the per-attempt timeout; the loop won't interrupt a hung call.

## Shape of a client

```rust,no_run
use quipu_client::{Client, Event, SendOutcome, Spool, Transport};
use quipu_core::{Content, EntityInput};

// 1. Adapt your HTTP library to the Transport seam.
struct MyHttp { /* reqwest::blocking::Client, base url, bearer token, ... */ }
impl Transport for MyHttp {
    fn send(&self, body: &[u8], idempotency_key: &str) -> SendOutcome {
        // POST `body` to {base}/v1/logs with Authorization + Idempotency-Key
        // headers and a per-attempt timeout, then classify per the table above.
        SendOutcome::Accepted
    }
}

// 2. Build a client with a disk spool for outage durability.
let spool = Spool::open("/var/lib/myservice/audit.spool")?;
let mut client = Client::new(MyHttp { /* ... */ }).with_spool(spool);

// 3. On startup and on a timer, flush anything buffered while down.
client.drain_spool()?;

// 4. Emit events; delivery never blocks on the server being up.
let event = Event::new(
    "user",
    EntityInput::new("u-42"),
    "POST",
    "/v1/transfer",
    Content::Text("wired 100".into()),
);
client.emit(&event)?; // -> Accepted | Spooled | Rejected | Dropped
# Ok::<(), std::io::Error>(())
```

`emit` returns a `Delivery`:

- `Accepted` — the server took it (or recognized a duplicate).
- `Spooled` — retries were spent; the event is durable on local disk, awaiting `drain_spool`. **Not a loss.**
- `Rejected { reason }` — the server permanently refused it (`Fatal`). Retrying or spooling won't help; log or quarantine it.
- `Dropped { reason }` — retries were spent and no spool is attached, so the event is gone. This is the only path where an event is lost — attach a spool to remove it.

## Tuning

`Backoff { base, max_delay, multiplier, max_retries }` controls the in-process retry schedule (defaults: 100 ms base, ×2, capped at 30 s, 6 retries). Set `max_retries: 0` to skip in-process retries entirely and let the spool absorb every failure — good when latency matters more than a synchronous attempt.

Call `drain_spool` on a timer *and* once at startup. The startup drain is what flushes events a previous process instance buffered before it stopped.
