# Quipu-Log

[English](README.md) | 한국어

**Rust 서비스를 위한 임베디드 변조 감지(tamper-evident) 감사 로그.**

Quipu-Log는 *누가 어떤 API를 통해 어떤 엔티티에 무엇을 했는지*를 기록하고,
나중에 다시 조회할 수 있게 해줍니다 — 엔티티가 **그 시점에** 가지고 있던
속성 값으로도 검색할 수 있습니다. 지난달에 사용자 이름이 바뀌었더라도,
변경 전에 기록된 로그는 여전히 옛 이름으로 표시되고 옛 이름으로 검색됩니다.

> *키푸(quipu)*는 잉카인들이 기록을 남기던 매듭 끈 장치입니다. 끈에 줄줄이
> 묶인 매듭은 하나를 몰래 다시 묶으면 티가 나기 마련이죠. 이 라이브러리가
> 여러분의 API에 해주는 일이 딱 그렇습니다.

## "그냥 JSON 로그 남기면 되지 않나?"와 다른 점

- **별도 데이터베이스가 필요 없습니다.** 스토리지는 순수 `std::fs` 위에
  구축된 append-only 세그먼트 스토어입니다: CRC 프레이밍된 레코드, 찢어진
  꼬리(torn tail)를 잘라내는 크래시 복구. 의존성 없는 단일 엔진이라 모든
  OS에서 동일하게 동작합니다.
- **변조가 드러납니다.** 각 레코드는 이전 레코드와 SHA-256 해시로 체이닝되며,
  이 체인은 세그먼트 파일 경계를 넘어 이어집니다. `store.verify_integrity()`는
  제자리에서 고쳐 쓴 레코드(CRC를 맞춰 놓았더라도)와 삭제·교체된 세그먼트를
  잡아냅니다.
- **쓰기가 핸들러를 막지 않습니다.** 이벤트는 큐에 들어가고 전용 writer
  스레드가 영속화합니다 — 재시도, 디스크 기반 데드레터 큐(DLQ), 그리고
  온콜 호출기에 연결할 수 있는 폴백 훅까지 갖추고 있습니다.
- **엔티티가 버전 관리됩니다.** 액터와 타깃은 타입별 레지스트리에 살고,
  모든 로그 행은 기록 시점에 최신이었던 버전을 정확히 고정(pin)합니다.
  시점 조회(time-travel)가 동작하는 이유입니다.

## 빠른 시작

```rust
use quipu_core::*;
use quipu_middleware::*;

// 1. 스토어를 연다 (없으면 생성).
let root = std::path::PathBuf::from("/var/lib/myapp/audit");
let cfg = StoreConfig::new(&root)
    .retention(RetentionPolicy::days(90))
    .sync_policy(SyncPolicy::EveryN(32));
let mut store = AuditStore::open(cfg)?;

// 2. 엔티티 타입 등록 (커스텀 스키마가 필요 없으면 기본 타입으로 충분).
if !store.has_type("default_actor") {
    store.define_type(default_actor_type())?;
    store.define_type(default_target_type())?;
}

// 3. 파이프라인을 시작하고 핸들을 잡아둔다.
let pipeline = AuditPipeline::start(
    store, root, PermissionPolicy::allow_all(),
    PipelineConfig::default(), None /* 폴백 훅 */)?;
let handle = pipeline.handle();

// 4. 이벤트 발행 — 논블로킹.
handle.emit(&Role::new("svc"), AuditEvent::new(...).target(...))?;
```

HTTP 서비스라면 4번 대신 [`tower` 프록시
레이어](#http-프록시로-기록하기)를 라우트 앞에 끼우면 됩니다.
실행 가능한 전체 예제는 [`examples/axum-demo`](examples/axum-demo)에 있습니다.

## 워크스페이스 구성

| crate | 설명 |
|---|---|
| `quipu-core` | 스토리지 엔진, 타입별 레지스트리, 필드 암호화, 보존 정책, 쿼리 |
| `quipu-middleware` | 이벤트 파이프라인(DLQ/폴백), pre/post 필터, 권한, `tower` 프록시 레이어 |
| `quipu-server` | 독립 데몬: 동일한 스토어를 토큰 인증 HTTP/JSON API 뒤에 두는 중앙 집중형 멀티 서비스 배포용 (해당 [README](crates/quipu-server/README.md) 참고) |
| `examples/axum-demo` | 실행 가능한 axum 연동 예제 |

## 데이터 모델

### 로그 행과 엔티티

로그 행에는 예상할 법한 컬럼들이 있습니다: `log_id`, `timestamp`(UTC
마이크로초), `actor`, `method`, `url`, `targets`, `content`, 그리고 직접
등록하는 커스텀 컬럼(text / number / json, 매 쓰기마다 검증).

`targets`는 관계 테이블(`log_id`, `entity_registry_uid`, `entity_type`)이라
하나의 로그가 여러 엔티티를 가리킬 수 있습니다. 타깃과 *액터 모두* 타입별
레지스트리 테이블에 저장되며, 필드 구성은 타입마다 직접 정합니다:

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

커스텀 스키마가 필요 없다면 기본 제공되는 `default_target`과
`default_actor`를 그대로 쓰면 됩니다.

### 필드 보호

보호 수준은 필드마다 따로 선택합니다. 기본값은 `None` — 디스크에 평문으로
저장됩니다. 보호는 필드 단위 옵트인이며, 스토어 전역 스위치는 없습니다.

| 수준 | 검색 | 키 | 비고 |
|---|---|---|---|
| `Sha256` | 정확 일치 | 불필요 | 단방향 해시. 쿼리 프로브도 같은 방식으로 해시되어 검색 가능. 주민번호처럼 엔트로피가 낮은 값은 디스크에서 무차별 대입이 가능하므로 `Hmac`을 쓸 것. |
| `Hmac` | 정확 일치 | `KeyRing::with_hmac_key` | 키 기반 HMAC-SHA-256. 키가 없는 사람에게는 무의미한 값. |
| `Rsa` | 불가(복호화 스캔) | RSA 키쌍 | AES-256-GCM + RSA-OAEP 키 래핑 하이브리드. 인증 암호화라 제자리 수정 시 복호화가 실패함. |

**적용 범위.** 보호는 레지스트리 *필드*에만 적용됩니다. 그 외는 모두 항상
평문입니다: `entity_id`, 로그의 `method`/`url`/`content`, 커스텀 컬럼 —
쿼리가 필터링하고 렌더링하는 대상이기 때문입니다. 실무적 결론: 민감한 값은
보호된 레지스트리 필드로 모델링하고, `entity_id`(주민번호 대신 불투명 ID
사용)와 `content`(요청/응답 덤프는 PII가 가장 새기 쉬운 곳)에는 넣지
마십시오.

### 보호된 필드 검색: 블라인드 인덱스

보호 수준이 쿼리가 할 수 있는 일을 결정합니다: 해시 필드는 정확 일치만,
RSA 필드는 전체 복호화 스캔이 필요합니다. 보호된 필드에 더 풍부한 검색이
필요하면 *블라인드 인덱스*를 달아주세요:

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // 정확 일치
    .search(FieldIndex::Ngram(3)),      // + 부분 문자열 일치
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + 최대 4자 접두사 일치
```

쓰기 시점에, 평문이 아직 손에 있을 때 소문자화된 토큰들을 다이제스트해서
레코드 옆에 함께 저장합니다 — `Exact`는 값 전체, `Prefix(n)`은 앞 1..=n자,
`Ngram(n)`은 n자 윈도우들. 평문이 디스크에 닿지 않아도 재시작 후에도 검색이
계속 동작하는 이유입니다.

토큰 다이제스트는 필드 자체의 다이제스트와 도메인 분리되어 있고, 필드와
같은 키 규율을 따릅니다(키 있는 필드는 토큰도 키를 사용). 따라서 선언한 것
이상의 오프라인 무차별 대입 표면은 늘어나지 않습니다. 다만 *구조*는
누설됩니다: 어떤 저장 값들이 접두사나 조각을 공유하는지 말이죠. 인덱스
선언은 이 트레이드오프를 필드 단위로 받아들이는 선택입니다 — 전역 스위치가
없는 이유입니다.

### 스키마 진화

타입 재정의는 추가만 가능합니다. 필드를 더할 수는 있지만, 기존 필드의
제거나 kind/보호 수준/검색 인덱스 변경은 불가합니다. 허용하면 "과거 값이
계속 검색된다"는 약속이 소리 없이 깨지기 때문입니다.

### 쓰기가 실제로 저장되는 과정

1. `define_type`이 타입의 레지스트리 테이블을 만듭니다(한 번만).
2. 매 쓰기마다 액터/타깃 엔티티가 각자의 레지스트리에 upsert됩니다. 필드가
   하나라도 바뀌었으면 새로운 불변 버전이 생성됩니다.
3. 로그 행은 액터의 버전 uid를 저장하고, 관계 행이 로그를 정확한 타깃
   버전들에 바인딩합니다.

버전은 불변이고 인덱싱되어 있습니다. 시점 조회가 동작하는 비결이 바로
이것입니다: 엔티티 이름을 바꿔도 옛 이름과 새 이름 모두 검색되고, 기존
로그는 기록 당시의 값을 그대로 보여줍니다.

## HTTP 프록시로 기록하기

일반적인 구성은 라우트 앞에 `tower` 레이어를 두는 것입니다:

```rust
let pipeline = AuditPipeline::start(store, root, permissions, PipelineConfig::default(),
    Some(Arc::new(|event, err| page_oncall(event, err))))?; // 폴백
let layer = AuditLayer::new(pipeline.handle())
    .rules(vec![EndpointRule::prefix("/api/docs").method(Method::PUT)
        .capture_request().capture_response()        // 캡처 한도를 넘는 본문은
        .capture_limit(1024 * 1024)                  //   캡처 없이 그대로 프록시
        .target_extractor(|req, res, req_body, res_body| {
            /* 규칙 단위 타깃 추출 (레이어 전역 설정을 오버라이드) */
            vec![]
        })])
    .filters(FilterSet::new()
        .pre(|req| /* 핸들러 전에 실행: 헬스 체크 제외 등 */)
        .post(|req, res, event| /* 핸들러 후에 실행: 304 스킵, 이벤트 보강 */))
    .target_extractor(|req, res, req_body, res_body| /* 타깃 엔티티 도출 */);
let app = Router::new().route(...).layer(layer);
```

HTTP를 거치지 않고 직접 이벤트를 발행할 수도 있습니다:

```rust
handle.emit(&Role::new("svc"), AuditEvent::new(...).target(...))?;  // 논블로킹
```

## 쿼리

```rust
let hits = handle.query(&Role::new("auditor"), LogQuery {
    targets: vec![          // 여러 필터는 AND로 결합
        // 정확 일치 — 과거 값 포함 (이름이 바뀐 엔티티도
        // 옛 이름으로 찾을 수 있음)
        TargetFilter::exact("default_target", "name", Value::Text("final-report".into())),
        // LIKE 스타일 부분 문자열 일치
        TargetFilter::exact("default_target", "name", Value::Text("report".into())).contains(),
    ],
    method: Some("PUT".into()),
    ..Default::default()
})?;
```

모든 검색 결과에는 기록 당시의 액터/타깃 스냅샷과 RFC 3339 UTC 타임스탬프가
함께 담겨 옵니다.

### 매칭 연산자

`exact`와 `contains()` 외에 `prefix()`와 `exact_ci()`(대소문자 무시 정확
일치)가 있습니다. 보호된 필드에서는 대응하는 `FieldIndex`(`Prefix(n)` /
`Exact`) 선언이 필요하며, 선언하면 거짓 양성 없이 매칭됩니다.

`contains()`의 동작은 필드에 따라 다릅니다:

- **평문 필드** — 항상 동작합니다: 인메모리 스캔, `Ngram` 인덱스가 선언돼
  있으면 후보 축소 후 스캔.
- **`Ngram(n)` 인덱스가 있는 보호 필드** — n자 이상의 프로브는 평문 개입
  없이 토큰 다이제스트로, 대소문자 무시하고 매칭됩니다. RSA 필드는 이후
  후보들을 복호화해 검증합니다(`StoreConfig::plaintext_cache(true)` 필요;
  전체 복호화 스캔이 후보 스캔으로 줄어듭니다). 단방향 해시 필드는 검증할
  평문이 없으므로, 히트는 "프로브의 조각을 모두 포함한다"는 뜻 — 거짓
  양성이 가능합니다. 정확한 히트가 필요하면 `Rsa`와 짝지어 쓰십시오.
- **인덱스 없는 보호 필드** — 레거시 폴백:
  `StoreConfig::plaintext_cache(true)`로 옵트인하면 RSA 값을 복호화해
  메모리에 캐시하고, 해시 필드는 현재 프로세스가 쓴 값의 평문을 유지합니다
  (디스크에 저장되지 않으며, 재시작 후에는 정확 일치만 가능). 캐시가 꺼져
  있으면 — 기본값 — 쿼리는 즉시 거부됩니다. 사용자가 요청하지도 않았는데
  평문을 몰래 메모리에 들고 있지 않기 위해서입니다.

### 스냅샷

쿼리는 읽기 스냅샷(`handle.snapshot(&role)?` / `store.snapshot()?`) 위에서
실행됩니다. 스냅샷 생성은 작은 인메모리 레지스트리 인덱스만 복제하고, 스캔은
호출자 스레드에서 돌기 때문에 느린 풀스캔 쿼리가 이벤트 영속화를 방해하지
않습니다.

### 레지스트리 둘러보기

```rust
handle.entity_types(&role)?;                            // 모든 타입 스키마
handle.list_entities(&role, "default_target", false)?;  // 엔티티별 최신 버전
handle.entity_history(&role, "default_target", "doc-1")?; // 모든 버전, 오래된 것부터
```

## 운영 노트

- **권한** — 역할 기반 `Emit` / `Query` / `Administer` 권한 부여, 허용
  목록 또는 거부 목록 모드.
- **보존 정책** — `RetentionPolicy::days(90)`은 봉인된 세그먼트를 통째로
  삭제하는 방식으로 오래된 데이터를 정리합니다: `unlink` 한 번, 재작성
  없음. 레지스트리는 유지되므로 오래된 이력도 계속 렌더링됩니다.
- **내구성** — `SyncPolicy::Always`(매 쓰기마다 fsync), `EveryN(n)`,
  `OsManaged` 중 선택.
- **데드레터 큐** — 재시도를 소진한 이벤트는 디스크에 보관되어 재시작에도
  살아남으며, `handle.redrive_dlq(&admin_role)`로 재처리할 수 있습니다.
  재처리는 크래시 안전합니다(실패분은 기존 큐가 교체되기 전에 스테이징되어
  내구성 있게 기록; 전달은 at-least-once). 재처리된 로그는 이벤트의 원래
  발생 시각을 유지하고, `required` 커스텀 컬럼은 소급 적용되지 않으므로
  오래 보관된 이벤트도 항상 재처리 가능합니다.
- **단일 프로세스 전용** — 스토어 루트는 OS 파일 잠금으로 보호되어, 같은
  루트를 여는 두 번째 프로세스는 데이터를 망가뜨리는 대신 즉시 실패합니다.
- **무결성 감사** — `store.verify_integrity()`가 모든 테이블의 해시 체인을
  순회하며 제자리에서 수정된 첫 레코드나 교체된 세그먼트를 보고합니다.
- **포맷 버저닝** — 세그먼트 파일은 매직 + 버전 바이트로 시작하므로, 향후
  레이아웃 변경을 오독 대신 마이그레이션으로 처리할 수 있습니다.
- **관측성** — 모든 쓰기 결과는 `tracing`으로 보고됩니다.

## 데모와 테스트 실행

```sh
cargo test                 # core + middleware 테스트 스위트
cargo run -p axum-demo     # 이후: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## 라이선스

Apache-2.0
