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

- `sync_policy`는 `"always"`, `"os_managed"`, `{ "every_n": N }` 중 하나입니다.
- `verify`(선택)는 주기적인 [무결성 검증](#무결성-검증)입니다.
  시작할 때 한 번, 이후 `interval_secs`마다 한 번씩 돕니다. 빼면 꺼집니다.
- 키 자료는 항상 파일 경로로 참조합니다. 설정 파일에 직접 넣을 수 없습니다.
- 인증은 기본 거부라서 권한을 받지 못한 역할은 아무것도 할 수 없습니다.
  토큰은 호출 서비스마다 하나씩 발급해서
  문제가 생기면 따로따로 폐기할 수 있게 해두세요.

### 토큰 관리

토큰은 **해시로** 저장하세요.
`sha256:<hex>` 형태의 키에는 토큰의 SHA-256만 들어가므로,
설정 파일이 유출돼도 그 자체로는 자격 증명이 되지 않습니다.
해시는 이렇게 만듭니다.

```sh
echo -n "$TOKEN" | shasum -a 256
```

평문 키도 여전히 동작합니다.
서버가 로드할 때 바로 해시하고 그 뒤로는 원문을 메모리에 들고 있지 않지만,
로드할 때마다 경고를 남깁니다.
이전 설정을 옮겨오는 동안만 쓰고, 거기에 머물지는 마세요.

토큰 값은 역할 이름 하나로 끝낼 수도 있고,
`{"role": ..., "expires": <unix epoch 초>}`처럼 만료를 붙일 수도 있습니다
(리눅스는 `date -d '+90 days' +%s`, macOS는 `date -v+90d +%s`).
`expires`를 지난 토큰은 모르는 토큰과 똑같이 401로 거절됩니다.
한때 유효했다는 힌트조차 주지 않습니다.

**핫 리로드.** `SIGHUP`을 보내면 설정 파일을 다시 읽어
`auth` 섹션(토큰, grants, `max_concurrent_queries`)만 갈아 끼웁니다.
재시작도, 연결 끊김도 없습니다.

```sh
kill -HUP "$(pgrep -f quipu-server)"
```

리로드할 때마다 추가/제거된 토큰 수를 로그에 남기므로
서버 로그가 곧 발급·회수 이력이 됩니다(토큰 원문은 절대 로그에 찍히지 않습니다).
파일을 못 읽거나, 파싱이 깨지거나, `sha256:` 키가 잘못된 경우에는
기존 인증 설정을 그대로 유지하고 에러만 남깁니다.
설정을 잘못 고쳤다고 돌아가는 서버가 잠기는 일은 없습니다.
나머지 섹션(`listen`, `store`, `keys`)은 여전히 재시작이 필요합니다.

**토큰별 쿼리 제한.** 쿼리는 풀스캔이라
토큰 하나가 CPU를 독차지하게 둘 수 없습니다.
`auth.max_concurrent_queries`는 토큰 하나가 동시에 돌릴 수 있는
쿼리 수의 상한입니다(생략하면 무제한).
상한에 닿은 토큰의 추가 쿼리는 **429**를 받으니,
돌고 있는 쿼리가 끝난 뒤 다시 시도하세요. 기록(append)에는 영향이 없습니다.

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

### 키 로테이션

위의 단일 파일 필드들은 **키 버전 1**로 읽힙니다.
로테이션할 때는 버전을 명시하는 목록 형태로 바꾸면 됩니다.
가장 높은 버전이 활성 키로 새 쓰기를 보호하고,
낮은 버전들은 옛 레코드를 읽는 데 쓰입니다:

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

키가 유출됐다면 서버를 내린 상태에서 오프라인 re-key까지 돌립니다.
RSA로 보호된 값을 새 키로 다시 감싸서, 옛 개인 키를 폐기할 수 있게 만드는 단계입니다:

```sh
quipu-server rekey /etc/quipu/config.json
```

전체 절차 — re-key가 해결하는 것과 못 하는 것, 그리고 변조와 어떻게 구분되는지 —
는 [최상위 README](../../README.ko.md#키-로테이션)에 있습니다.

## TLS

설정에 `tls` 섹션을 넣으면 서버가 직접 TLS를 종단합니다(rustls).

```json
"tls": {
  "cert_pem_file": "/etc/quipu/tls/cert.pem",
  "key_pem_file": "/etc/quipu/tls/key.pem"
}
```

`keys`와 마찬가지로 인증서와 개인 키는 파일 경로로만 참조합니다.
설정 파일에 직접 넣을 수 없습니다.

"리버스 프록시 뒤에 두세요"라는 문서 한 줄로 끝내지 않고
직접 종단을 넣은 이유는 이렇습니다.
모든 요청에 bearer 토큰과 감사 데이터(PII가 섞일 수 있는)가 실려 다니니,
전송 구간은 이 서버의 위협 모델 안에 있습니다.
그걸 프록시에 맡기면 신뢰 경계가 프로젝트 바깥으로 밀려나고,
단독 배포에서는 보안 약속이 자기 힘으로 성립하지 않게 됩니다.

물론 TLS를 종단해 주는 프록시나 서비스 메시 뒤에서 돌리는 것도 여전히 됩니다.
`tls` 섹션을 빼면 예전처럼 평문 HTTP로 동작합니다.

로컬 테스트용 자가서명 인증서는 이렇게 만듭니다.

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout key.pem -out cert.pem
```

## HTTP API

`/v1/healthz`만 빼고 모든 엔드포인트에 `Authorization: Bearer <token>`이 필요합니다.
오류는 `{"error": "<message>"}` 형태로 옵니다.
401은 토큰 누락·미등록·만료, 403은 역할에 권한 없음, 400은 스키마나 암호화 오용,
404는 없음, 409는 무결성 검증이 이미 돌고 있다는 뜻(끝난 뒤 다시 시도하세요),
429는 그 토큰의 동시 쿼리 상한 도달(돌던 쿼리가 끝나면 재시도하세요),
503은 큐가 가득 찼다는 뜻(백오프 후 재시도하세요), 그 외는 500입니다.

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
| `POST /v1/admin/verify` | administer | 검증 리포트(아래 참고). 이미 돌고 있으면 **409** |

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

## 무결성 검증

모든 테이블은 해시 체인입니다
(`sha256(직전 체인 값 || payload)`, 세그먼트 경계를 넘어도 이어집니다).
그래서 기록을 제자리에서 고치거나 세그먼트를 빼돌리고 바꿔치기하면
나중에라도 들통납니다.
임베디드에서는 `AuditStore::verify_integrity()`로 확인하는데,
서버는 같은 검사를 두 가지 방법으로 노출합니다.

**필요할 때** — `POST /v1/admin/verify` (administer 권한):

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

체인이 끊긴 걸 찾았다면 그건 검증이 *제대로 일한* 겁니다.
그래서 응답은 여전히 200이고, 대신 `"ok": false`와 함께
끊긴 지점이 `problems`에 담겨 옵니다
(검증은 첫 번째 끊김에서 멈추므로 항목은 많아야 하나입니다).
검증 자체를 돌리지 못했을 때만 에러 상태 코드가 나갑니다.

**주기적으로** — 설정에 `verify` 섹션을 넣으세요.

```json
"verify": { "interval_secs": 86400 }
```

시작할 때 한 번 돌고, 그 뒤로는 interval마다 한 번씩 돕니다.
체인 끊김을 찾거나 검증을 돌리지 못하면 `error` 레벨로 로그를 남기니,
알림은 그 로그 라인에 걸어 두면 됩니다.
섹션을 빼면 주기 검증만 꺼지고 엔드포인트는 그대로 동작합니다.

cron을 걸기 전에 알아둘 것 두 가지:

- 검증은 한 번에 하나만 돕니다. 엔드포인트와 주기 태스크가 같은 자리를
  나눠 쓰므로, 누가 돌고 있는 동안 엔드포인트는 **409**를 주고
  주기 태스크는 경고만 남기고 그 차례를 건너뜁니다.
- 검증은 모든 세그먼트를 **writer 스레드에서** 다시 읽습니다
  (체인이 스토어의 단일 writer 잠금 아래에 있기 때문입니다).
  도는 동안 기록 요청은 디스크에 적히는 대신 파이프라인 큐에 쌓입니다.
  보통 크기의 스토어라면 문제없지만, 아주 큰 스토어에 쓰기가 몰리는
  환경이라면 한가한 시간대에 돌리거나
  검증 중 `POST /v1/logs`가 일부 503을 받을 수 있다고 보면 됩니다.

## v1에서 의도적으로 둔 제약

- 스토어도 하나, 테넌트도 하나입니다.
  토큰이 가르는 것은 할 수 있는 일(emit/query/admin)이지 볼 수 있는 데이터가 아니라서,
  모든 reader가 모든 로그를 봅니다.
  테넌트 격리는 테넌트마다 스토어 루트를 따로 두는 일이라 다음 과제로 남겨뒀습니다.
- Rust 클라이언트 crate는 아직 없습니다.
  다만 위 API는 어떤 HTTP 클라이언트로도 부를 수 있을 만큼 작습니다.
  gRPC가 아니라 JSON을 고른 이유이기도 합니다.
