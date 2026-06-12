# quipu-server

[English](README.md) | 한국어

독립 실행형 감사 로그 데몬입니다.
임베디드 `quipu-core` 스토어를 `quipu-middleware`의 비동기 파이프라인으로 감싸
HTTP/JSON API로 노출합니다.
언어가 무엇이든 여러 서비스가 감사 로그를 한곳에 기록하고 검색할 수 있습니다
(Elasticsearch처럼 중앙에 두는 배포 형태).
임베디드 모드를 대체하는 게 아니라, 같은 엔진을 돌리는 또 하나의 방법입니다.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

스토어가 단일 프로세스 전용(`root/LOCK`)이라는 점은 그대로이고,
그 한 프로세스가 바로 이 데몬입니다.
기록 요청은 파이프라인의 크기 제한 큐와 writer 스레드(재시도, 디스크 기반 DLQ)를 거치고,
쿼리는 blocking 풀에서 시점 스냅샷 위에 실행됩니다.
그래서 느린 스캔이 돌고 있어도 수집은 멈추지 않습니다.

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

- `sync_policy`는 `"always"`, `"os_managed"`, `{ "every_n": N }` 중 하나입니다.
- 키 자료는 항상 파일 경로로 참조합니다. 설정 파일에 직접 넣을 수 없습니다.
- 인증은 기본 거부라서 권한을 받지 못한 역할은 아무것도 할 수 없습니다.
  토큰은 호출 서비스마다 하나씩 발급해서
  문제가 생기면 따로따로 폐기할 수 있게 해두세요.

### 키 경계

서버에 쥐여줄 것은 두 가지뿐입니다.
보호 필드의 쓰기와 동등 검색에 쓰는 **HMAC 키**,
그리고 암호화 필드의 쓰기에 쓰는 **RSA 공개 키**.

`private_key_pem_file`을 설정하지 않으면 서버는 쓰기 전용으로 돕니다.
쿼리는 되지만 RSA로 보호된 값은
암호문(`{"Rsa": {wrapped_key, nonce, ciphertext}}`) 그대로 돌려주고,
받아간 클라이언트가 `KeyRing::decrypt`로 자기 자리에서 복호화합니다.
서버가 뚫려도 평문은 못 건지는 구성이죠.

반대로 개인 키까지 설정하고 `plaintext_cache: true`를 켜면
RSA 보호 필드도 서버에서 `contains` 검색이 되지만,
그만큼 서버가 그 값을 읽을 수 있게 됩니다.

## HTTP API

`/v1/healthz`만 빼고 모든 엔드포인트에 `Authorization: Bearer <token>`이 필요합니다.
오류는 `{"error": "<message>"}` 형태로 옵니다.
401은 토큰 누락이나 미등록, 403은 역할에 권한 없음, 400은 스키마나 암호화 오용,
404는 없음, 503은 큐가 가득 찼다는 뜻(백오프 후 재시도하세요), 그 외는 500입니다.

| 메서드 & 경로 | 권한 | 본문 / 응답 |
|---|---|---|
| `GET /v1/healthz` | — | `ok` |
| `POST /v1/types` | administer | `TypeSchema` JSON → 204. 재정의는 추가만 가능. |
| `GET /v1/types` | query | `[TypeSchema]` |
| `POST /v1/columns` | administer | `CustomColumnDef` JSON → 204 |
| `POST /v1/logs` | emit | 기록 요청 → **202** `{"status":"queued"}` |
| `POST /v1/logs/query` | query | `LogQuery` JSON → `[LogView]` |
| `GET /v1/entities/{type}?include_deleted=` | query | `[TargetSnapshot]` (최신 버전) |
| `GET /v1/entities/{type}/{id}/history` | query | `[TargetSnapshot]` (오래된 것부터) |
| `POST /v1/admin/flush` | administer | 큐에 쌓인 것 전부 fsync → 204 |
| `POST /v1/admin/redrive` | administer | `{"redriven": n}` |
| `POST /v1/admin/retention` | administer | `{"segments_dropped": n}` |
| `GET /v1/admin/dlq` | administer | `{"parked": n}` |

202는 큐에 들어갔다는 뜻이지 디스크에 안전하게 적혔다는 뜻이 아닙니다.
거기서부터는 파이프라인이 책임집니다.
실패하면 재시도하고, 그래도 안 되면 DLQ로 보내며, 어떤 것도 조용히 버리지 않습니다.
비동기 검증에서 떨어진 이벤트(예: 정의되지 않은 actor 타입)도 DLQ에 보관되니
`GET /v1/admin/dlq`를 모니터링하세요.

### 로그 기록

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

- `occurred_at`(UTC 마이크로초)을 생략하면 서버가 받은 시각으로 기록됩니다.
  클라이언트 쪽에서 큐잉이나 재시도를 한다면,
  행동이 실제로 일어난 시각을 직접 넣어 주세요.
- 값에는 태그를 붙입니다.
  `{"Text": "..."}`, `{"Number": 1.5}`, `{"Json": "<json을 문자열로>"}` 중 하나입니다.
  디스크 포맷이 타입 정보를 따로 들고 있지 않아서 JSON은 문자열로 감쌉니다.
  `content`도 같은 방식으로 `Text`/`Json`을 받습니다.

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

조건은 전부 선택 사항이고, 적은 것끼리는 AND로 묶입니다
(`{}`를 보내면 `limit` 한도까지 전체 반환).
`mode`는 `"exact"`(기본), `"exact_ci"`, `"prefix"`, `"contains"` 중 하나입니다.
`include_past`는 기본이 `true`라서 이름이 바뀐 엔티티도 옛 이름으로 찾을 수 있습니다.
결과는 `LogView` 행으로,
로그와 함께 기록 당시 모습 그대로의 actor/target 스냅샷이 담겨 옵니다.

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

규칙은 임베디드의 `define_type`과 같습니다. 재정의는 추가만 됩니다.

## v1에서 의도적으로 둔 제약

- 스토어도 하나, 테넌트도 하나입니다.
  토큰이 가르는 것은 할 수 있는 일(emit/query/admin)이지 볼 수 있는 데이터가 아니라서,
  모든 reader가 모든 로그를 봅니다.
  테넌트 격리는 테넌트마다 스토어 루트를 따로 두는 일이라 다음 과제로 남겨뒀습니다.
- HTTP는 평문입니다. 리버스 프록시나 서비스 메시 같은 TLS 뒤에 두세요.
- Rust 클라이언트 crate는 아직 없습니다.
  다만 위 API는 어떤 HTTP 클라이언트로도 부를 수 있을 만큼 작습니다.
  gRPC가 아니라 JSON을 고른 이유이기도 합니다.
