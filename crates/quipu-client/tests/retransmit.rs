//! The retransmission contract end to end: retries, fatal short-circuit,
//! spool-on-exhaustion, and spool replay — all against a scripted transport so
//! no network or real time is involved.

use quipu_client::{
    Client, Delivery, Event, SendOutcome, Sleeper, Spool, SpoolRecord, Transport,
};
use quipu_core::{Content, EntityInput};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A transport driven by a queue of scripted outcomes. Records the
/// idempotency key of every attempt so tests can assert it stays stable across
/// retries.
struct ScriptedTransport {
    outcomes: Mutex<std::collections::VecDeque<SendOutcome>>,
    /// Fallback once the script is drained.
    default: SendOutcome,
    keys: Mutex<Vec<String>>,
    calls: AtomicUsize,
}

impl ScriptedTransport {
    fn new(script: Vec<SendOutcome>, default: SendOutcome) -> Self {
        Self {
            outcomes: Mutex::new(script.into()),
            default,
            keys: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn keys(&self) -> Vec<String> {
        self.keys.lock().unwrap().clone()
    }
}

impl Transport for ScriptedTransport {
    fn send(&self, _body: &[u8], idempotency_key: &str) -> SendOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.keys.lock().unwrap().push(idempotency_key.to_string());
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| self.default.clone())
    }
}

/// No-op sleeper so the backoff loop runs without wall-clock delay.
struct NoSleep;
impl Sleeper for NoSleep {
    fn sleep(&self, _dur: std::time::Duration) {}
}

fn sample_event() -> Event {
    Event::new(
        "user",
        EntityInput::new("u-1"),
        "POST",
        "/v1/transfer",
        Content::Text("hi".into()),
    )
}

fn retry(reason: &str) -> SendOutcome {
    SendOutcome::Retry {
        reason: reason.into(),
    }
}

#[test]
fn accepts_on_first_try() {
    let t = ScriptedTransport::new(vec![SendOutcome::Accepted], SendOutcome::Accepted);
    let mut client = Client::new(t).sleeper(Box::new(NoSleep));
    assert_eq!(client.emit(&sample_event()).unwrap(), Delivery::Accepted);
}

#[test]
fn retries_then_succeeds_with_one_stable_key() {
    let script = vec![retry("down"), retry("down"), SendOutcome::Accepted];
    let t = ScriptedTransport::new(script, SendOutcome::Accepted);
    // borrow the transport's recording by constructing it inside an Arc-free
    // pattern: pull the keys back out after the client is dropped
    let mut client = Client::new(t).sleeper(Box::new(NoSleep));
    assert_eq!(client.emit(&sample_event()).unwrap(), Delivery::Accepted);
    // recover the transport to inspect it
    let t = into_transport(client);
    assert_eq!(t.calls(), 3, "two retries then success");
    let keys = t.keys();
    assert_eq!(keys.len(), 3);
    assert!(
        keys.windows(2).all(|w| w[0] == w[1]),
        "the idempotency key must be identical across retries: {keys:?}"
    );
}

#[test]
fn fatal_does_not_retry() {
    let t = ScriptedTransport::new(
        vec![SendOutcome::Fatal {
            reason: "401".into(),
        }],
        SendOutcome::Accepted,
    );
    let mut client = Client::new(t).sleeper(Box::new(NoSleep));
    match client.emit(&sample_event()).unwrap() {
        Delivery::Rejected { reason } => assert_eq!(reason, "401"),
        other => panic!("expected Rejected, got {other:?}"),
    }
    let t = into_transport(client);
    assert_eq!(t.calls(), 1, "fatal must not retry");
}

#[test]
fn dropped_when_retries_exhausted_and_no_spool() {
    // default Retry forever; backoff caps retries, so it eventually gives up
    let t = ScriptedTransport::new(vec![], retry("down"));
    let mut client = Client::new(t)
        .sleeper(Box::new(NoSleep))
        .backoff(quipu_client::Backoff {
            max_retries: 3,
            ..Default::default()
        });
    match client.emit(&sample_event()).unwrap() {
        Delivery::Dropped { .. } => {}
        other => panic!("expected Dropped, got {other:?}"),
    }
    let t = into_transport(client);
    assert_eq!(t.calls(), 4, "1 initial + 3 retries");
}

#[test]
fn spools_when_retries_exhausted_then_drains() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.spool");

    // first client: server is down the whole time -> event lands in the spool
    {
        let t = ScriptedTransport::new(vec![], retry("down"));
        let spool = Spool::open(&path).unwrap();
        let mut client = Client::new(t)
            .sleeper(Box::new(NoSleep))
            .backoff(quipu_client::Backoff {
                max_retries: 2,
                ..Default::default()
            })
            .with_spool(spool);
        assert_eq!(client.emit(&sample_event()).unwrap(), Delivery::Spooled);
        assert_eq!(client.spooled().unwrap(), 1);
    }

    // a brand-new client (simulating a restart) opens the same spool and
    // drains it once the server is back
    {
        let t = ScriptedTransport::new(vec![SendOutcome::Accepted], SendOutcome::Accepted);
        let spool = Spool::open(&path).unwrap();
        assert_eq!(spool.len().unwrap(), 1, "spooled event survived the restart");
        let mut client = Client::new(t).sleeper(Box::new(NoSleep)).with_spool(spool);
        let report = client.drain_spool().unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.kept, 0);
        assert_eq!(client.spooled().unwrap(), 0, "spool emptied after delivery");
    }
}

#[test]
fn drain_keeps_records_while_still_failing() {
    let dir = tempfile::tempdir().unwrap();
    let mut spool = Spool::open(dir.path().join("a.spool")).unwrap();
    for i in 0..3 {
        spool
            .append(&SpoolRecord {
                idempotency_key: format!("key-{i}"),
                body: format!("{{\"n\":{i}}}").into_bytes(),
            })
            .unwrap();
    }
    // server still down: nothing delivered, all kept, order preserved
    let t = ScriptedTransport::new(vec![], retry("down"));
    let report = spool.drain(&t).unwrap();
    assert_eq!(report.delivered, 0);
    assert_eq!(report.kept, 3);
    assert_eq!(spool.len().unwrap(), 3);
    let keys: Vec<String> = spool.read_all().unwrap().into_iter().map(|r| r.idempotency_key).collect();
    assert_eq!(keys, ["key-0", "key-1", "key-2"]);
}

#[test]
fn torn_tail_is_truncated_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("torn.spool");
    {
        let mut spool = Spool::open(&path).unwrap();
        spool
            .append(&SpoolRecord {
                idempotency_key: "good".into(),
                body: b"{}".to_vec(),
            })
            .unwrap();
    }
    // append a half-written frame: a length header promising bytes that aren't there
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&999u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(b"partial").unwrap();
    }
    let spool = Spool::open(&path).unwrap();
    let records = spool.read_all().unwrap();
    assert_eq!(records.len(), 1, "torn tail dropped, whole record kept");
    assert_eq!(records[0].idempotency_key, "good");
}

/// Recover the transport from a client for post-hoc assertions. Mirrors how a
/// real caller would keep an `Arc` to it; here we just reconstruct via a field
/// move helper kept in the test.
fn into_transport(client: Client<ScriptedTransport>) -> ScriptedTransport {
    client.into_transport()
}
