# quipu-server

[English](README.md) | 한국어

독립 실행형 감사 로그 데몬. 임베디드 `quipu-core` 스토어를
`quipu-middleware`의 비동기 파이프라인으로 감싸 HTTP/JSON API로 노출합니다.
덕분에 언어에 상관없이 여러 서비스가 감사 로그를 중앙에서 기록·검색할 수
있습니다(Elasticsearch 스타일의 배포 형태). 임베디드 모드는 그대로
동작합니다 — 같은 엔진을 돌리는 두 번째 방법이지 대체재가 아닙니다.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

스토어는 여전히 단일 프로세스 전용이고(`root/LOCK`), 그 프로세스가 바로 이
데몬입니다. 추가(append)는 파이프라인의 유한 큐 + writer 스레드(재시도,
디스크 기반 DLQ)를 거치고, 쿼리는 blocking 풀에서 시점 스냅샷 위에
실행되므로 느린 스캔이 수집(ingestion)을 멈추게 하지 않습니다.

## 실행

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
      "s3rv1ce-a-t0ken": "writer",
      "aud1tor-t0ken": "reader",
      "adm1n-t0ken": "admin"
    },
    "grants": {
      "writer": ["emit"],
      "reader": ["query"],
      "admin": ["emit", "query", "administer"]
    }
  }
}
```

- `sync_policy`: `"always"`, `"os_managed"`, 또는 `{ "every_n": N }`.
- 키 자료는 항상 파일 경로로 참조하며, 설정에 직접 넣지 않습니다.
- 인증은 기본 거부(deny-by-default)입니다: 권한이 없는 역할은 아무것도 할
  수 없습니다. 호출 서비스마다 토큰을 하나씩 발급해 개별 폐기가 가능하게
  운영하십시오.

### 키 경계

서버에 필요한 것은 **HMAC 키**(보호 필드의 쓰기 + 동등 검색)와 **RSA 공개
키**(암호화 필드의 쓰기)뿐입니다. `private_key_pem_file`을 설정하지 않으면
서버는 쓰기 전용으로 동작합니다: 쿼리는 여전히 되지만 RSA로 보호된 값은
암호문(`{"Rsa": {wrapped_key, nonce, ciphertext}}`)으로 반환되고, 조회한
클라이언트가 `KeyRing::decrypt`로 로컬에서 복호화합니다. 평문 복원 능력을
서버의 피해 반경 밖에 두는 구성입니다. 개인 키를 설정하면(+
`plaintext_cache: true`) RSA 보호 필드에 대한 서버 측 `contains` 검색이
가능해지지만, 그 대가로 서버가 해당 값을 읽을 수 있게 됩니다.

## HTTP API

`/v1/healthz`를 제외한 모든 엔드포인트는 `Authorization: Bearer <token>`이
필요합니다. 오류는 `{"error": "<message>"}` 형태이며 401(토큰 누락/미등록),
403(역할에 해당 권한 없음), 400(스키마/암호화 오용), 404, 503(추가 큐 가득
참 — 백오프 후 재시도), 500을 반환합니다.

| 메서드 & 경로 | 권한 | 본문 / 응답 |
|---|---|---|
| `GET /v1/healthz` | — | `ok` |
| `POST /v1/types` | administer | `TypeSchema` JSON → 204. 재정의는 추가만 가능. |
| `GET /v1/types` | query | `[TypeSchema]` |
| `POST /v1/columns` | administer | `CustomColumnDef` JSON → 204 |
| `POST /v1/logs` | emit | 추가 요청 → **202** `{"status":"queued"}` |
| `POST /v1/logs/query` | query | `LogQuery` JSON → `[LogView]` |
| `GET /v1/entities/{type}?include_deleted=` | query | `[TargetSnapshot]` (최신 버전) |
| `GET /v1/entities/{type}/{id}/history` | query | `[TargetSnapshot]` (오래된 것부터) |
| `POST /v1/admin/flush` | administer | 큐에 쌓인 것 전부 fsync → 204 |
| `POST /v1/admin/redrive` | administer | `{"redriven": n}` |
| `POST /v1/admin/retention` | administer | `{"segments_dropped": n}` |
| `GET /v1/admin/dlq` | administer | `{"parked": n}` |

202는 *큐에 들어갔다*는 뜻이지 내구성이 확보됐다는 뜻이 아닙니다 — 내구성은
파이프라인의 몫입니다(재시도, 그다음 DLQ; 아무것도 조용히 버려지지
않습니다). 비동기 검증에 실패한 이벤트(예: 정의되지 않은 액터 타입)는 DLQ에
보관됩니다. `GET /v1/admin/dlq`를 모니터링하십시오.

### 로그 추가

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

- `occurred_at`(UTC 마이크로초)은 선택 사항이며 기본값은 서버의 "지금"
  입니다. 클라이언트 쪽에서 큐잉/재시도를 한다면 행동이 실제로 일어난
  시각이 기록되도록 직접 지정하십시오.
- 값에는 태그가 붙습니다: `{"Text": "..."}`, `{"Number": 1.5}`, 또는
  `{"Json": "<json을 문자열로>"}`(디스크 포맷이 자기 기술적이지 않아
  문자열로 감쌉니다). `content`도 같은 방식으로 `Text`/`Json`을 받습니다.

### 쿼리

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

설정된 조건은 모두 AND로 결합되며, 전부 선택 사항입니다(`{}`는 `limit`까지
전체 반환). 필터 필드: `mode`는 `"exact"`(기본), `"exact_ci"`, `"prefix"`,
`"contains"` 중 하나. `include_past`는 기본값이 `true`입니다(이름이 바뀐
엔티티도 옛 이름으로 찾을 수 있음). 결과는 `LogView` 행: 로그와 함께 기록
당시 그대로의 액터/타깃 스냅샷이 담겨 옵니다.

### 타입 정의

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

임베디드 `define_type`과 같은 규칙: 재정의는 추가만 가능합니다.

## 제약 사항 (v1, 의도된 설계)

- 스토어 하나, 테넌트 하나: 토큰이 분리하는 것은 *능력*(emit/query/admin)
  이지 데이터가 아닙니다 — 모든 reader가 모든 로그를 봅니다. 테넌트별
  격리는 테넌트별 스토어 루트를 의미하며 향후 작업입니다.
- 평문 HTTP — TLS 뒤에 두십시오(리버스 프록시 또는 서비스 메시).
- Rust 클라이언트 crate는 아직 없습니다. 위 API는 어떤 HTTP 클라이언트로도
  호출할 수 있을 만큼 작은데, gRPC 대신 JSON을 고른 이유가 바로 그것입니다.
