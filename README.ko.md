# Quipu-Log

[English](README.md) | 한국어

**Rust 서비스를 위한 변조 감지(tamper-evident) 감사 로그. 라이브러리로 임베드되며, 따로 돌려야 할 데이터베이스가 없습니다.**

"지난 분기에 이 문서를 누가 고쳤지? 그때는 문서 이름이 뭐였더라?" —
Quipu-Log는 이런 질문에 답하려고 만든 라이브러리입니다.

누가 어떤 API로 어떤 대상에 무엇을 했는지 기록하되,
모든 레코드를 이전 레코드와 해시로 엮어 몰래 고치면 흔적이 남게 하고,
로그를 쓰던 그 순간의 엔티티 모습까지 함께 보존합니다.
오늘 사용자 이름을 바꿔도 지난달 로그에는 여전히 옛 이름이 찍혀 있고,
옛 이름으로 검색해도 나옵니다.

> 이름은 잉카의 매듭 끈 기록 장치 *키푸(quipu)*에서 따왔습니다.
> 끈에 줄줄이 묶인 매듭은 하나만 몰래 다시 묶어도 티가 나니까요.

## 왜 만들었나

감사 로깅은 보통 "적당히 JSON으로 만들어 어딘가에 쌓아두기"로 시작합니다.
평소에는 그걸로 그럭저럭 굴러가는데, 막상 감사를 받게 되면 세 가지 문제가 한꺼번에 드러납니다.
파일을 만질 수 있는 사람이 이력을 고쳐도 알아챌 방법이 없고,
옛 로그에 적힌 이름과 속성은 이미 낡았거나 애초에 적히지도 않았고,
"X에 관한 로그 전부"를 찾으려니 반쯤 구조화된 텍스트를 grep하는 수밖에 없습니다.
로그를 DB 테이블로 옮기면 셋째는 풀리지만 앞의 둘은 그대로입니다.

Quipu-Log는 이 세 가지를 사고 난 뒤의 회고거리가 아니라
처음부터 설계 요구사항으로 놓고 만들었습니다.

- **변조가 드러납니다.**
  스토리지는 append-only이고, 모든 레코드는 파일 경계를 넘어 이전 레코드와 SHA-256 해시로 이어집니다.
  제자리에서 고쳐 쓴 레코드든 통째로 바꿔치기된 세그먼트든 `store.verify_integrity()`가 첫 지점을 짚어냅니다.
  CRC를 맞춰 놓아도 소용없습니다.
- **이력이 맥락을 잃지 않습니다.**
  로그에 등장하는 사람과 사물은 버전이 관리되는 엔티티로 저장됩니다.
  그래서 과거 로그는 기록 당시에 참이었던 값 그대로 표시되고 검색됩니다.
- **따로 운영할 게 없습니다.**
  스토어는 순수 `std::fs`로만 관리되는 디렉토리 하나입니다.
  레코드는 CRC로 프레이밍하고, 크래시가 나면 쓰다 만 꼬리를 잘라내는 것으로 복구합니다.
  데몬도 외부 의존성도 없으니 어느 OS에서나 똑같이 동작합니다.
- **핸들러가 디스크를 기다리지 않습니다.**
  쓰기는 비동기 파이프라인을 거칩니다.
  실패하면 재시도하고, 그래도 안 되면 디스크 기반 데드레터 큐(DLQ)에 보관하며,
  최종 실패는 폴백 훅으로 받아 온콜 알림에 연결할 수 있습니다.

## 동작 원리

감사 기록 하나는 **이벤트** 하나입니다.
누가(*actor* — 사용자나 서비스) 무엇에(*target* — 하나 이상 가능)
무언가를(`method`, `url`, 필요하면 요청/응답 내용까지) 했다는 사실이죠.

이때 actor와 target은 자유 형식 문자열이 아니라 **엔티티**입니다.
**타입**별로 필드 구성을 직접 정의하는 구조화된 레코드이고,
타입마다 스토어 안에 전용 **레지스트리**가 하나씩 생깁니다.

레지스트리는 값을 덮어쓰는 법이 없습니다.
엔티티의 필드가 바뀌면 불변 **버전**이 새로 추가될 뿐이고,
로그 행은 기록 시점에 최신이었던 버전을 정확히 가리켜 둡니다(pin).
시점 조회(time-travel)의 비결이 전부 여기에 있습니다.
옛 값과 새 값이 둘 다 인덱스에 남아 있고,
각 로그는 자신이 실제로 본 값을 그대로 보여줍니다.

```
핸들러 ──emit──▶ 파이프라인 ──────────▶ 스토어 (append-only, 해시 체인)
        (논블로킹) (큐, 재시도,           ├── logs
                   DLQ, 폴백)            └── 레지스트리 (버전 관리되는 엔티티)
```

코드 쪽에서는 가볍게 복제할 수 있는 파이프라인 **핸들**만 들고 있으면 됩니다.
스토어는 전용 writer 스레드가 소유하고, 영속화도 그 스레드가 합니다.

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

전체가 돌아가는 예제는 [`examples/axum-demo`](examples/axum-demo)에 있습니다.
HTTP 서비스라면 보통 emit을 직접 부를 일이 없으니 바로 다음 섹션을 보세요.

## HTTP에서 기록하기

가장 흔한 구성은 라우트 앞에 `tower` 레이어를 끼우는 것입니다.
어떤 엔드포인트를 기록할지, 본문을 캡처할지,
요청에서 target 엔티티를 어떻게 뽑을지를 레이어가 담당합니다.

```rust
let pipeline = AuditPipeline::start(store, root, permissions, PipelineConfig::default(),
    Some(Arc::new(|event, err| page_oncall(event, err))))?; // 폴백
let layer = AuditLayer::new(pipeline.handle())
    .rules(vec![EndpointRule::prefix("/api/docs").method(Method::PUT)
        .capture_request().capture_response()        // 캡처 한도를 넘는 본문은
        .capture_limit(1024 * 1024)                  //   캡처 없이 그대로 프록시
        .target_extractor(|req, res, req_body, res_body| {
            /* 규칙 단위 target 추출 (레이어 전역 설정을 오버라이드) */
            vec![]
        })])
    .filters(FilterSet::new()
        .pre(|req| /* 핸들러 전에 실행: 헬스 체크 제외 등 */)
        .post(|req, res, event| /* 핸들러 후에 실행: 304 스킵, 이벤트 보강 */))
    .target_extractor(|req, res, req_body, res_body| /* target 엔티티 도출 */);
let app = Router::new().route(...).layer(layer);
```

배치 작업이나 운영 스크립트처럼 HTTP 요청이 아닌 일에는
레이어와 별개로 `handle.emit(...)`을 그대로 쓰면 됩니다.

## 데이터 모델링

### 엔티티 타입

로그 행에는 `log_id`, `timestamp`(UTC 마이크로초), `actor`, `method`, `url`, `targets`, `content`가 들어가고,
필요하면 커스텀 컬럼(text / number / json, 매 쓰기마다 검증)을 등록해 늘릴 수 있습니다.
`targets`는 관계 테이블이라 로그 하나가 여러 엔티티를 가리킬 수 있습니다.

모델링에서 정작 중요한 건 엔티티 스키마 쪽입니다.
타입마다 필드 구성을 직접 정합니다.

```rust
store.define_type(TypeSchema::new("patient", vec![
    FieldDef::text("ssn").protection(FieldProtection::Hmac).indexed().required(),
    FieldDef::text("mrn").protection(FieldProtection::Sha256).indexed(),
    FieldDef::text("name").protection(FieldProtection::Rsa),
]))?;
```

커스텀 스키마가 필요 없다면 기본 제공되는 `default_actor`와 `default_target`으로 충분합니다.
빠른 시작에서 등록한 게 바로 이 둘입니다.

### 필드 보호

보호 수준은 필드마다 따로 고릅니다.
기본은 평문 저장이고, 스토어 전체를 한 번에 켜는 스위치는 일부러 만들지 않았습니다.
무엇을 보호할지는 필드 하나하나의 모델링 결정이기 때문입니다.

| 수준 | 검색 | 키 | 비고 |
|---|---|---|---|
| `Sha256` | 정확 일치 | 불필요 | 단방향 해시. 검색어도 같은 방식으로 해시해 비교합니다. 주민번호처럼 엔트로피가 낮은 값은 디스크만 손에 넣으면 무차별 대입이 되므로 `Hmac`을 쓰세요. |
| `Hmac` | 정확 일치 | `KeyRing::with_hmac_key` | 키 기반 HMAC-SHA-256. 키가 없으면 아무 의미 없는 값입니다. |
| `Rsa` | 불가(복호화 스캔) | RSA 키쌍 | AES-256-GCM에 RSA-OAEP 키 래핑을 더한 하이브리드. 인증 암호화라 제자리에서 고치면 복호화가 실패합니다. |

적용 범위는 미리 알아두는 게 좋습니다.
보호는 레지스트리 **필드에만** 걸립니다.
`entity_id`, 로그의 `method`/`url`/`content`, 커스텀 컬럼은 항상 평문인데,
쿼리가 필터링하고 화면에 보여주는 대상이 바로 이것들이기 때문입니다.

그러니 민감한 값은 보호된 필드에 담고,
엔티티 ID에는 주민번호 같은 것 대신 무의미한 값을 쓰고,
`content`에는 PII를 넣지 마세요.
캡처된 요청 본문이야말로 PII가 가장 새기 쉬운 곳입니다.

### 블라인드 인덱스: 암호화한 값을 검색하기

보호를 걸면 검색이 좁아집니다.
해시 필드는 정확 일치만 되고, RSA 필드는 전체를 복호화하며 스캔해야 하죠.
*블라인드 인덱스*를 달면 그 폭을 다시 넓힐 수 있습니다.

```rust
FieldDef::text("ssn").protection(FieldProtection::Hmac)
    .indexed()                          // 정확 일치
    .search(FieldIndex::Ngram(3)),      // + 부분 문자열 일치
FieldDef::text("name").protection(FieldProtection::Rsa)
    .search(FieldIndex::Prefix(4)),     // + 최대 4자 접두사 일치
```

원리는 이렇습니다.
쓰기 시점에는 평문이 아직 손에 있으니,
그때 소문자로 정규화한 토큰들을 다이제스트해서 레코드 옆에 같이 저장합니다.
`Exact`는 값 전체를, `Prefix(n)`은 앞 1..=n자를, `Ngram(n)`은 n자 윈도우들을요.
평문은 디스크에 닿지 않지만 검색은 재시작 후에도 계속 됩니다.

물론 공짜는 아닙니다.
토큰 다이제스트는 필드의 키 사용 방식을 그대로 따르기 때문에(키로 보호되는 필드면 토큰에도 키가 들어갑니다)
무차별 대입의 여지가 선언한 것 이상으로 늘지는 않지만, *구조*는 새어 나갑니다.
어떤 저장 값들끼리 접두사나 조각을 공유하는지가 보이게 되죠.
인덱스를 선언한다는 건 그 필드 하나에 한해 이 거래를 받아들이겠다는 뜻이고,
여기에 전역 스위치가 없는 것도 같은 이유입니다.

### 스키마 진화

타입 재정의는 추가만 됩니다.
새 필드는 더할 수 있지만, 기존 필드를 지우거나 kind·보호 수준·인덱스를 바꾸는 건 막혀 있습니다.
이걸 허용하면 "과거 값은 계속 검색된다"는 약속이 소리 없이 깨지기 때문입니다.

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

검색 결과 한 건마다 기록 당시 모습 그대로의 actor/target 스냅샷과
RFC 3339 UTC 타임스탬프가 함께 옵니다.

### 매칭 연산자

`exact`와 `contains()` 말고도 `prefix()`, 그리고 대소문자를 무시하는 `exact_ci()`가 있습니다.
평문 필드에서는 넷 다 그냥 동작합니다.
보호된 필드에서 `prefix()`와 `exact_ci()`는 대응하는 `FieldIndex`를 선언해야 하고,
선언만 하면 거짓 양성 없이 매칭됩니다.
신경 쓸 게 있는 쪽은 `contains()`입니다.

- `Ngram(n)` 인덱스가 있으면 n자 이상의 검색어를 토큰 다이제스트만으로,
  평문 없이, 대소문자 구분 없이 매칭합니다.
  RSA 필드는 추려진 후보를 복호화해 한 번 더 검증합니다(`StoreConfig::plaintext_cache(true)` 필요).
  단방향 해시 필드는 검증할 평문 자체가 없어서,
  히트는 "검색어의 조각을 전부 갖고 있다"는 뜻에 그칩니다.
  거짓 양성이 섞일 수 있으니 정확한 히트가 필요한 필드라면 `Rsa`를 쓰세요.
- 인덱스가 없으면 보호된 필드의 `contains()`는 `StoreConfig::plaintext_cache(true)`를 켜야만 동작합니다.
  복호화했거나 이 프로세스가 직접 쓴 값을 메모리에 들고 있는 방식이라
  (디스크에는 안 남고, 재시작하면 사라집니다)
  기본값인 캐시 꺼짐 상태에서는 쿼리를 그냥 거부합니다.
  부탁하지도 않은 평문을 슬그머니 메모리에 쌓아두지 않기 위해서입니다.

### 스냅샷과 레지스트리 둘러보기

쿼리는 읽기 스냅샷(`handle.snapshot(&role)?`) 위에서 돕니다.
스냅샷을 뜨는 비용은 작은 인메모리 레지스트리 인덱스를 복제하는 정도이고,
스캔은 호출한 쪽 스레드에서 돌기 때문에
아무리 느린 풀스캔도 이벤트 영속화를 방해하지 못합니다.

```rust
handle.entity_types(&role)?;                            // 모든 타입 스키마
handle.list_entities(&role, "default_target", false)?;  // 엔티티별 최신 버전
handle.entity_history(&role, "default_target", "doc-1")?; // 모든 버전, 오래된 것부터
```

## 서버 모드: 여러 서비스, 하나의 로그

여기까지는 전부 임베디드 실행,
그러니까 스토어가 서비스 프로세스 안에 사는 방식이었습니다.
`quipu-server`는 같은 엔진을 독립 데몬으로 돌려 토큰 인증 HTTP/JSON API로 노출합니다.
언어가 무엇이든 여러 서비스가 감사 로그를 한곳에 기록하고 검색할 수 있게 됩니다.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

스토어가 단일 프로세스 전용이라는 점은 그대로이고,
그 한 프로세스가 바로 이 데몬입니다.
인증은 기본 거부에 토큰마다 역할 권한을 부여하는 방식입니다.

서버를 쓰기 전용으로 띄울 수도 있습니다.
RSA 개인 키 없이 시작하면 암호화 필드를 저장은 하되 조회 때는 암호문 그대로 돌려주고,
복호화는 클라이언트가 자기 자리에서 합니다.
서버가 뚫려도 평문은 못 건지는 구성입니다.

설정 방법과 전체 HTTP API, v1 제약은
[quipu-server README](crates/quipu-server/README.ko.md)에 있습니다.

## 운영 노트

- **권한** — `Emit` / `Query` / `Administer`를 역할 단위로 부여합니다.
  허용 목록과 거부 목록 모드 중 고를 수 있습니다.
- **보존 정책** — `RetentionPolicy::days(90)`은 봉인된 세그먼트를 통째로 지우는 방식입니다.
  `unlink` 한 번이면 끝나고 다시 쓰는 일이 없습니다.
  레지스트리는 남겨두므로 오래된 이력도 계속 렌더링됩니다.
- **내구성** — 매 쓰기마다 fsync하는 `SyncPolicy::Always`, `EveryN(n)`, `OsManaged` 중에서 고릅니다.
- **데드레터 큐** — 재시도를 다 써버린 이벤트는 디스크에 보관되어 재시작해도 남아 있고,
  `handle.redrive_dlq(&admin_role)`로 다시 흘려보낼 수 있습니다.
  재처리는 크래시에 안전하고 at-least-once입니다.
  재처리된 로그는 원래 발생 시각을 유지하고,
  `required` 커스텀 컬럼을 소급해서 따지지 않으므로
  오래 묵은 이벤트도 언제든 재처리할 수 있습니다.
- **단일 프로세스 전용** — 스토어 루트는 OS 파일 잠금으로 지킵니다.
  같은 루트를 여는 두 번째 프로세스는 데이터를 망치는 대신 곧바로 실패합니다.
- **무결성 감사** — `store.verify_integrity()`가 모든 테이블의 해시 체인을 따라가며,
  제자리에서 수정된 첫 레코드나 바꿔치기된 세그먼트를 보고합니다.
- **포맷 버저닝** — 세그먼트 파일은 매직 넘버와 버전 바이트로 시작합니다.
  나중에 레이아웃이 바뀌어도 잘못 읽는 대신 마이그레이션으로 처리할 수 있습니다.
- **관측성** — 쓰기 결과 하나하나가 `tracing`으로 보고됩니다.
- **키 로테이션** — 바로 아래 절에서 다룹니다.
  키를 바꿔도 옛 데이터는 계속 검색·복호화되고,
  유출된 RSA 키는 정말로 은퇴시킬 수 있습니다.

### 키 로테이션

`KeyRing`의 모든 키에는 **버전**(1 이상)이 붙습니다.
종류별로 가장 높은 버전이 *활성* 키가 되어 새 쓰기를 전부 보호하고,
저장되는 값에는 어떤 버전으로 보호했는지가 함께 기록됩니다.
낮은 버전들은 읽기 전용 재료로 링에 남습니다.
복호화는 레코드가 가리키는 버전의 개인 키를 꺼내 쓰고,
검색은 들고 있는 모든 버전의 HMAC 키로 다이제스트를 만들어 견줘 보기 때문에,
키를 바꿨다고 옛 레코드가 검색 결과에서 슬그머니 빠지는 일은 없습니다.

**평시 로테이션**(유출 정황 없음)은 더 높은 버전을 하나 얹는 것이 전부입니다:

```rust
let keys = KeyRing::new()
    .with_hmac_key_version(1, old_hmac)?      // 보존: 옛 다이제스트 검색용
    .with_hmac_key_version(2, new_hmac)?      // 활성: 새 쓰기 다이제스트
    .with_private_pem_version(1, old_rsa)?    // 보존: 옛 값 복호화용
    .with_private_pem_version(2, new_rsa)?;   // 활성: 새 값 암호화
```

(서버라면 설정의 `hmac_keys` / `rsa_keys` 목록이 같은 역할을 합니다.)
이걸로 끝입니다 — 옛 레코드는 그대로 동작하고 새 레코드는 새 키를 씁니다.
은퇴한 *공개* 키는 계속 보관하세요.
옛 체크포인트와 re-key 이벤트는 서명 당시 버전의 키로 검증됩니다.

**유출 시 강제 로테이션**은 여기에 오프라인 **re-key** 단계를 더해서,
새어 나간 RSA 개인 키로는 저장된 데이터를 더 이상 읽을 수 없게 만듭니다:

1. 서비스를 내립니다 (스토어 디렉토리 백업도 함께).
2. 옛 키를 남겨둔 채 설정에 새 키 버전을 추가합니다.
3. `quipu-server rekey <config.json>`을 실행합니다
   (임베디드라면 `AuditStore::rekey()`).
   RSA로 보호된 모든 레지스트리 값의 데이터 키를 옛 개인 키로 풀어
   새 공개 키로 다시 감싸고,
   RSA 필드의 블라인드 인덱스 토큰도 새 HMAC 키로 다시 만듭니다.
4. 출력된 요약을 확인한 뒤 **옛 RSA 개인 키를 폐기합니다** —
   이제 그 키로는 스토어의 어떤 값도 복호화할 수 없습니다.
   옛 *HMAC* 키는 폐기하면 안 되고(아래 참고), 옛 공개 키도 남겨둡니다.
5. 서비스를 다시 올립니다.

re-key는 레지스트리 테이블을 다시 쓰는 작업이라 해시 체인이 새로 생기는데,
이는 변조가 남기는 흔적과 똑같이 생겼습니다.
그래서 re-key는 레지스트리마다 "옛 체인 헤드 → 새 체인 헤드" 전환을 기록한
**서명된 re-key 이벤트**를 (체인으로 묶인) 메타 테이블에 남깁니다.
이후 `verify_integrity()`는 모든 re-key 서명을 검증하고,
각 레지스트리 체인에 최신 이벤트가 서명한 헤드가 아직 들어 있는지 확인합니다.
감사 기록이 있는 re-key와 말 없는 재작성이 그렇게 구분됩니다.

솔직한 한계 두 가지.
HMAC 다이제스트는 일방향이고 평문은 디스크에 없으므로
HMAC 필드는 re-key가 *불가능합니다* —
기록된 버전을 그대로 유지하고, 검색을 위해 옛 HMAC 키를 계속 보관해야 하며,
HMAC 키가 한 번 새면 그 키로 쓴 다이제스트는 영구히 노출된 것입니다
(엔트로피 낮은 값은 무차별 대입 대상이 되고,
로테이션은 그 시점 이후의 쓰기만 보호합니다).
그리고 re-key의 범위는 레지스트리입니다.
로그 행의 `method`/`url`/`content`는 설계상 평문이라 돌릴 키 자체가 없습니다.

## 워크스페이스 구성

| crate | 설명 |
|---|---|
| `quipu-core` | 스토리지 엔진, 타입별 레지스트리, 필드 암호화, 보존 정책, 쿼리 |
| `quipu-middleware` | 이벤트 파이프라인(DLQ/폴백), pre/post 필터, 권한, `tower` 프록시 레이어 |
| `quipu-server` | 독립 데몬: 같은 스토어 엔진을 토큰 인증 HTTP/JSON API로 노출 |
| `examples/axum-demo` | 실행 가능한 axum 연동 예제 |

## 데모와 테스트 실행

```sh
cargo test                 # core + middleware 테스트 스위트
cargo run -p axum-demo     # 이후: curl -X PUT localhost:3000/api/docs/42 -H 'x-audit-actor: alice' -d hi
```

## 라이선스

Apache-2.0
