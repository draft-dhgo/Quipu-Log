# quipu-client

[English](README.md)

[`quipu-server`](../quipu-server/README.ko.md)용 레퍼런스 클라이언트다. **단일 노드** 서버를
상대로 호출 서비스가 감사 이벤트를 안정적으로 기록하기 위한 프로토콜을 담았다 — 그 노드가
잠깐 닿지 않더라도 기록을 잃지 않는다.

## 왜 클라이언트 크레이트가 필요한가

`quipu-server`는 설계상 단일 프로세스다. 파일 락이 해시 체인 스토어를 단일 writer로 묶고,
바로 그 점이 위변조 탐지를 단순하게 만든다([루트 README의 스코프
절](../../README.ko.md#가용성과-스코프-의도된-단일-노드) 참고). 대가는 데몬이 가용성의 단일
장애점이 된다는 것이다. 데몬이 죽었거나 쓰기 큐가 가득 차 있는 동안, 아무 대비 없는 호출자의
감사 기록은 그대로 멈춘다. 감사 로그에서 이건 일시적 잡음이 아니라 컴플라이언스 구멍이다.

체인을 여러 노드로 복제해 증명을 복잡하게 만드는 대신, 이 프로젝트는 그 부담을 송신 측으로
옮긴다 — 거기서는 가용성 확보가 싸고 로컬에서 끝난다. 이 크레이트가 그 계약의 송신 측
레퍼런스 구현이다.

## 무엇을 제공하나

- **멱등 재전송** — 이벤트마다 안정적인 `Idempotency-Key`를 실어 모든 재시도에서 같은 키를
  쓴다. 서버가 이미 받은 POST를 다시 보내도 중복으로 인식돼 두 번째 기록이 되지 않는다.
- **지터를 곁들인 지수 백오프** — 일시적 실패는 상한이 정해진 무작위 스케줄로 재시도한다.
  장애 복구 직후 다수 클라이언트가 한꺼번에 재접속해 회복 중인 데몬을 덮치는 일을 막는다.
- **옵트인 로컬 디스크 스풀** — 재시도를 다 써도 이벤트를 버리지 않고 로컬 파일에 append(+fsync)
  했다가 서버가 돌아오면 재생한다. "데몬이 죽었다"를 *기록 유실*에서 *기록 지연 도착*으로
  바꾼다. 서버가 이벤트마다 클라이언트가 찍은 `occurred_at`을 보존하므로, 이 지연은 최종
  로그에 드러나지 않는다. 스풀은 스토어 세그먼트와 똑같이 CRC 프레이밍을 써서, 크래시로
  찢어진 꼬리는 다음 open 때 탐지·절단된다.

## HTTP 의존성 없음

이 크레이트는 HTTP 클라이언트를 품지 않는다. 이미 쓰고 있는 것(`reqwest`, `ureq`, 직접 만든
소켓)을 메서드 하나짜리 `Transport` 트레잇으로 끼우면 된다. 그 트레잇의 유일한 일은 POST 한
번을 `SendOutcome`으로 분류하는 것이다:

| HTTP 결과 | `SendOutcome` |
|---|---|
| `202 {"status":"queued"}` | `Accepted` |
| `202 {"status":"duplicate"}` | `Duplicate` (성공 — 키가 제 역할을 했다) |
| 연결/타임아웃/리셋, `408`/`429`/`502`/`503`/`504` | `Retry` |
| `400`/`401`/`403`/`404` | `Fatal` (재시도 금지; 스풀은 거절을 재생할 뿐) |

이 분류가 계약의 전부다 — 재시도 루프는 이 네 결과만 안다. 시도별 타임아웃도 transport가
책임진다. 루프는 멈춘 호출을 중단시키지 않는다.

## 클라이언트의 모양

```rust,no_run
use quipu_client::{Client, Event, SendOutcome, Spool, Transport};
use quipu_core::{Content, EntityInput};

// 1. 쓰던 HTTP 라이브러리를 Transport 자리에 끼운다.
struct MyHttp { /* reqwest::blocking::Client, base url, bearer token, ... */ }
impl Transport for MyHttp {
    fn send(&self, body: &[u8], idempotency_key: &str) -> SendOutcome {
        // {base}/v1/logs 로 body를 POST. Authorization + Idempotency-Key 헤더와
        // 시도별 타임아웃을 붙이고, 위 표대로 분류한다.
        SendOutcome::Accepted
    }
}

// 2. 장애 내구성을 위해 디스크 스풀을 단 클라이언트를 만든다.
let spool = Spool::open("/var/lib/myservice/audit.spool")?;
let mut client = Client::new(MyHttp { /* ... */ }).with_spool(spool);

// 3. 시작 시점과 타이머마다, 죽어 있는 동안 버퍼된 것을 비운다.
client.drain_spool()?;

// 4. 이벤트를 보낸다. 전송은 서버가 살아 있는지에 막히지 않는다.
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

`emit`은 `Delivery`를 돌려준다:

- `Accepted` — 서버가 받았다(또는 중복으로 인식했다).
- `Spooled` — 재시도를 다 썼고, 이벤트는 로컬 디스크에 내구성 있게 남아 `drain_spool`을
  기다린다. **유실이 아니다.**
- `Rejected { reason }` — 서버가 영구 거절했다(`Fatal`). 재시도·스풀로도 해결 안 됨. 로그하거나
  격리한다.
- `Dropped { reason }` — 재시도를 다 썼는데 스풀이 없어서 이벤트가 사라졌다. 이벤트가 유실되는
  유일한 경로 — 스풀을 달면 이 경로가 없어진다.

## 튜닝

`Backoff { base, max_delay, multiplier, max_retries }`로 인프로세스 재시도 스케줄을 조절한다
(기본값: base 100 ms, ×2, 상한 30 s, 재시도 6회). `max_retries: 0`으로 두면 인프로세스 재시도를
건너뛰고 모든 실패를 스풀이 흡수하게 한다 — 동기 시도보다 지연이 더 중요할 때 적합하다.

`drain_spool`은 타이머로 *그리고* 시작 시점에 한 번 호출한다. 시작 시점 드레인이, 이전 프로세스
인스턴스가 멈추기 전에 버퍼해 둔 이벤트를 비우는 단계다.
