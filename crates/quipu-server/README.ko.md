# quipu-server

[English](README.md) | 한국어

독립 실행형 감사 로그 데몬입니다. 임베디드 `quipu-core` 스토어를 `quipu-middleware`의 비동기 파이프라인으로 감싸 HTTP/JSON API로 노출합니다. 언어가 무엇이든 여러 서비스가 감사 로그를 한곳에 기록하고 검색할 수 있습니다(Elasticsearch처럼 중앙에 두는 배포 형태). 임베디드 모드를 대체하는 게 아니라, 같은 엔진을 돌리는 또 하나의 방법입니다.

```
service A ──┐                       ┌── root/logs
service B ──┼── HTTP ── quipu-server┼── root/registry/<type>
auditor  ───┘   (bearer tokens)     └── root/dlq, ...
```

스토어가 단일 프로세스 전용(`root/LOCK`)이라는 점은 그대로이고, 그 한 프로세스가 바로 이 데몬입니다. 기록 요청은 파이프라인의 크기 제한 큐와 writer 스레드(재시도, 디스크 기반 DLQ)를 거칩니다. 쿼리는 blocking 풀에서 시점 스냅샷 위에 실행되므로, 느린 스캔이 돌고 있어도 수집은 멈추지 않습니다.

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

- `sync_policy`는 `"always"`, `"os_managed"`, `{ "every_n": N }` 중 하나입니다.
- `retention_days`와 `retention_max_bytes`(둘 다 선택)는 각각 보존 기간과 로그·관계 테이블의 용량 한도입니다. 두 조건은 **OR**로 묶입니다 — 어느 쪽이든 한도를 넘는 순간 가장 오래된 봉인 세그먼트부터 지웁니다.
- `access_log`(선택, 기본 false)는 메타 감사입니다. 스토어를 향한 모든 쿼리와 관리 작업을 전용 접근 로그에 남기고, `POST /v1/access/query`로 읽습니다. `access_retention_days`는 접근 로그만의 보존 기간으로, `retention_days`와는 따로 갑니다(빼면 접근 기록을 계속 보관합니다).
- `verify`(선택)는 주기적인 [무결성 검증](#무결성-검증)입니다. 시작할 때 한 번, 이후 `interval_secs`마다 한 번씩 돕니다. 빼면 꺼집니다.
- `health`(선택)는 디스크 여유 공간 경고 기준(둘 중 하나만 걸려도 경고, 위 값이 기본값)과 [디스크가 가득 찼을 때의 동작](#디스크가-가득-차면)입니다.
- 키 자료는 항상 파일 경로로 참조합니다. 설정 파일에 직접 넣을 수 없습니다.
- 인증은 기본 거부라서, 권한을 받지 못한 역할은 아무것도 할 수 없습니다. 토큰은 호출 서비스마다 하나씩 발급해, 문제가 생기면 따로따로 폐기할 수 있게 해두세요.

### 토큰 관리

토큰은 **해시로** 저장하세요. `sha256:<hex>` 형태의 키에는 토큰의 SHA-256만 들어가므로, 설정 파일이 유출돼도 그 자체로는 자격 증명이 되지 않습니다. 해시는 이렇게 만듭니다.

```sh
echo -n "$TOKEN" | shasum -a 256
```

평문 키도 여전히 동작합니다. 서버가 로드할 때 바로 해시하고 그 뒤로는 원문을 메모리에 들고 있지 않지만, 로드할 때마다 경고를 남깁니다. 이전 설정을 옮겨오는 동안만 쓰고, 거기에 머물지는 마세요.

토큰 값은 역할 이름 하나로 끝낼 수도 있고, `{"role": ..., "expires": <unix epoch 초>}`처럼 만료를 붙일 수도 있습니다(리눅스는 `date -d '+90 days' +%s`, macOS는 `date -v+90d +%s`). `expires`를 지난 토큰은 모르는 토큰과 똑같이 401로 거절됩니다. 한때 유효했다는 힌트조차 주지 않습니다.

**핫 리로드.** `SIGHUP`을 보내면 설정 파일을 다시 읽어 `auth` 섹션(토큰, grants, `max_concurrent_queries`)만 갈아 끼웁니다. 재시작도, 연결 끊김도 없습니다.

```sh
kill -HUP "$(pgrep -f quipu-server)"
```

리로드할 때마다 추가·제거된 토큰 수를 로그에 남기므로, 서버 로그가 곧 발급·회수 이력이 됩니다(토큰 원문은 절대 로그에 찍히지 않습니다). 파일을 못 읽거나, 파싱이 깨지거나, `sha256:` 키가 잘못된 경우에는 기존 인증 설정을 그대로 유지하고 에러만 남깁니다. 설정을 잘못 고쳤다고 돌아가는 서버가 잠기는 일은 없습니다. 나머지 섹션(`listen`, `store`, `keys`)은 여전히 재시작이 필요합니다.

**토큰별 쿼리 제한.** 쿼리는 풀스캔이라 토큰 하나가 CPU를 독차지하게 둘 수 없습니다. `auth.max_concurrent_queries`는 토큰 하나가 동시에 돌릴 수 있는 쿼리 수의 상한입니다(생략하면 무제한). 상한에 닿은 토큰의 추가 쿼리는 **429**를 받으니, 돌고 있는 쿼리가 끝난 뒤 다시 시도하세요. 기록(append)에는 영향이 없습니다.

### 키 경계

서버에 쥐여줄 것은 두 가지뿐입니다. 보호 필드의 쓰기와 동등 검색에 쓰는 **HMAC 키**, 그리고 암호화 필드의 쓰기에 쓰는 **RSA 공개 키**입니다.

`private_key_pem_file`을 설정하지 않으면 서버는 쓰기 전용으로 돕니다. 쿼리는 되지만 RSA로 보호된 값은 암호문(`{"Rsa": {wrapped_key, nonce, ciphertext}}`) 그대로 돌려주고, 받아간 클라이언트가 `KeyRing::decrypt`로 자기 자리에서 복호화합니다. 서버가 뚫려도 평문은 못 건지는 구성이죠.

반대로 개인 키까지 설정하고 `plaintext_cache: true`를 켜면 RSA 보호 필드도 서버에서 `contains` 검색이 됩니다. 그만큼 서버가 그 값을 읽을 수 있게 됩니다.

### 키 로테이션

위의 단일 파일 필드들은 **키 버전 1**로 읽힙니다. 로테이션할 때는 버전을 명시하는 목록 형태로 바꾸면 됩니다. 가장 높은 버전이 활성 키로 새 쓰기를 보호하고, 낮은 버전들은 옛 레코드를 읽는 데 쓰입니다.

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

평시 로테이션(유출 없음)은 여기서 끝입니다. 옛 레코드는 그대로 동작하고, 새 쓰기는 가장 높은 버전을 씁니다. 키가 **유출**됐다면, 새어 나간 RSA 개인 키로 저장된 데이터를 더는 읽을 수 없도록 오프라인 re-key를 돌립니다.

1. 서비스를 내리고 스토어 디렉토리를 백업합니다.
2. 옛 키를 남겨둔 채 설정에 새 키 버전을 추가합니다.
3. re-key를 실행합니다. RSA로 보호된 모든 값을 옛 개인 키로 풀어 새 공개 키로 다시 감싸고, RSA 필드의 블라인드 인덱스 토큰도 새 HMAC 키로 다시 만듭니다.

   ```sh
   quipu-server rekey /etc/quipu/config.json   # 임베디드라면 AuditStore::rekey()
   ```
4. 출력된 요약을 확인한 뒤 **옛 RSA 개인 키를 폐기합니다.** 이제 그 키로는 스토어의 어떤 값도 복호화할 수 없습니다. 옛 HMAC 키와 옛 공개 키는 남겨둡니다.
5. 서비스를 다시 올립니다.

re-key는 레지스트리 테이블을 다시 쓰는 작업이라 해시 체인이 새로 생기는데, 이는 변조가 남기는 흔적과 똑같이 생겼습니다. 그래서 re-key는 레지스트리마다 "옛 체인 헤드 → 새 체인 헤드" 전환을 기록한 **서명된 re-key 이벤트**를 체인으로 묶인 메타 테이블에 남깁니다. `verify_integrity()`는 모든 re-key 서명을 검증하고, 각 체인에 최신 이벤트가 서명한 헤드가 아직 있는지 확인합니다. 감사된 re-key와 말 없는 재작성이 그렇게 구분됩니다.

한계 두 가지. HMAC 필드는 일방향이고 평문이 디스크에 없어 re-key가 **안 됩니다.** 검색을 위해 옛 HMAC 키를 계속 보관해야 하고, HMAC 키가 한 번 새면 그 키로 쓴 다이제스트는 영구히 노출된 것입니다. 그리고 re-key의 범위는 레지스트리입니다. 로그 행의 `method`/`url`/`content`는 설계상 평문이라 돌릴 키가 없습니다.

## TLS

설정에 `tls` 섹션을 넣으면 서버가 직접 TLS를 종단합니다(rustls).

```json
"tls": {
  "cert_pem_file": "/etc/quipu/tls/cert.pem",
  "key_pem_file": "/etc/quipu/tls/key.pem"
}
```

`keys`와 마찬가지로 인증서와 개인 키는 파일 경로로만 참조합니다. 설정 파일에 직접 넣을 수 없습니다.

"리버스 프록시 뒤에 두세요" 한 줄로 끝내지 않고 직접 종단을 넣은 이유는 이렇습니다. 모든 요청에 bearer 토큰과 감사 데이터(PII가 섞일 수 있는)가 실려 다니니, 전송 구간이 이 서버의 위협 모델 안에 있습니다. 그걸 프록시에 맡기면 신뢰 경계가 프로젝트 바깥으로 밀려나고, 단독 배포에서는 보안 약속이 자기 힘으로 성립하지 않게 됩니다.

물론 TLS를 종단해 주는 프록시나 서비스 메시 뒤에서 돌리는 것도 됩니다. `tls` 섹션을 빼면 예전처럼 평문 HTTP로 동작합니다.

로컬 테스트용 자가서명 인증서는 이렇게 만듭니다.

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' \
  -keyout key.pem -out cert.pem
```

## HTTP API

`/v1/healthz`만 빼고 모든 엔드포인트에 `Authorization: Bearer <token>`이 필요합니다. 오류는 `{"error": "<message>"}` 형태로 옵니다. 401은 토큰 누락·미등록·만료, 403은 역할에 권한 없음, 400은 스키마나 암호화 오용, 404는 없음, 409는 무결성 검증이 이미 돌고 있다는 뜻(끝난 뒤 다시 시도하세요), 429는 그 토큰의 동시 쿼리 상한 도달(돌던 쿼리가 끝나면 재시도하세요), 503은 큐가 가득 찼다는 뜻(백오프 후 재시도하세요), 507은 디스크가 가득 찬 상태에서 `reject_emit_when_disk_full`이 켜져 있다는 뜻(더 길게 백오프하세요), 그 외는 500입니다.

전체 기계 판독용 계약은 **`GET /v1/openapi.json`**(OpenAPI 3.1, 인증 불필요 — 데이터가 아니라 인터페이스 설명이므로)으로 서빙됩니다. 코드 제너레이터나 Swagger UI를 여기에 물리세요. 아래 표는 사람용 요약입니다.

| 메서드 & 경로 | 권한 | 본문 / 응답 |
|---|---|---|
| `GET /v1/healthz` | — | `{"status": "ok"/"degraded"/"unhealthy", "reasons": [...]}` — [헬스 체크](#헬스-체크) 참고 |
| `GET /metrics` | administer | Prometheus 텍스트 포맷 — [메트릭](#메트릭) 참고 |
| `GET /v1/openapi.json` | — | 이 API의 OpenAPI 3.1 문서 |
| `POST /v1/types` | administer | `TypeSchema` JSON → 204. 재정의는 추가만 가능. |
| `GET /v1/types` | query | `[TypeSchema]` |
| `POST /v1/columns` | administer | `CustomColumnDef` JSON → 204 |
| `POST /v1/logs` | emit | 기록 요청 → **202** `{"status":"queued"}` |
| `POST /v1/logs/query` | query | `LogQuery` JSON → `{"logs": [LogView], "next_cursor"?, "segments_scanned"}` |
| `POST /v1/logs/count` | query | `LogQuery` JSON → `{"count": n}` (렌더링·복호화 없음) |
| `POST /v1/logs/export` | query | `LogQuery` JSON → `application/x-ndjson` (한 줄에 `LogView` 하나) |
| `GET /v1/entities/{type}?include_deleted=` | query | `[TargetSnapshot]` (최신 버전) |
| `GET /v1/entities/{type}/{id}/history` | query | `[TargetSnapshot]` (오래된 것부터) |
| `POST /v1/access/query` | administer | `AccessQuery` JSON(`from_micros`/`to_micros`/`actor`/`operation`/`limit`, 모두 선택) → `[AccessRecord]`. 메타 감사 — 누가 스토어를 조회·관리했는지. `store.access_log: true`가 필요합니다(아니면 400). 이 조회 자체도 정확히 한 건씩 기록됩니다. |
| `POST /v1/admin/flush` | administer | 큐에 쌓인 것 전부 fsync → 204 |
| `POST /v1/admin/redrive` | administer | `{"redriven": n, "requeued": n, "quarantined_entries": n, "quarantined_segments": n}` — 손상된 DLQ 데이터는 redrive를 실패시키는 대신 `<dlq>.quarantine/`으로 격리 |
| `POST /v1/admin/retention` | administer | `{"segments_dropped": n}` |
| `GET /v1/admin/dlq` | administer | `{"parked": n}` |
| `POST /v1/admin/verify` | administer | 검증 리포트(아래 참고). 이미 돌고 있으면 **409** |

202는 큐에 들어갔다는 뜻이지 디스크에 안전하게 적혔다는 뜻이 아닙니다. 거기서부터는 파이프라인이 책임집니다. 실패하면 재시도하고, 그래도 안 되면 DLQ로 보내며, 어떤 것도 조용히 버리지 않습니다. 비동기 검증에서 떨어진 이벤트(예: 정의되지 않은 actor 타입)도 DLQ에 보관되니 `GET /v1/admin/dlq`를 모니터링하세요.

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

- `occurred_at`(UTC 마이크로초)을 생략하면 서버가 받은 시각으로 기록됩니다. 클라이언트 쪽에서 큐잉이나 재시도를 한다면, 행동이 실제로 일어난 시각을 직접 넣어 주세요.
- 값에는 태그를 붙입니다. `{"Text": "..."}`, `{"Number": 1.5}`, `{"Json": "<json을 문자열로>"}` 중 하나입니다. 디스크 포맷이 타입 정보를 따로 들고 있지 않아 JSON은 문자열로 감쌉니다. `content`도 같은 방식으로 `Text`/`Json`을 받습니다.

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

조건은 전부 선택 사항이고, 적은 것끼리는 AND로 묶입니다(`{}`를 보내면 `limit` 한도까지 전체 반환). `mode`는 `"exact"`(기본), `"exact_ci"`, `"prefix"`, `"contains"` 중 하나입니다. `include_past`는 기본이 `true`라서 이름이 바뀐 엔티티도 옛 이름으로 찾을 수 있습니다. 결과는 `LogView` 행으로, 로그와 함께 기록 당시 모습 그대로의 actor/target 스냅샷이 담겨 옵니다.

응답은 한 **페이지**입니다.

```json
{
  "logs": [ ... ],
  "next_cursor": "AQEDAAAAAAAAACkAAAAAAAAA",
  "segments_scanned": 2
}
```

- `order`는 `"desc"`(기본 — 최신부터, 그래서 `limit`은 "최신 N건"이라는 뜻) 또는 `"asc"`입니다. 시간 범위(`from_micros`/`to_micros`)를 주면 범위 밖 세그먼트 파일은 아예 열지도 않습니다.
- 매치가 더 남아 있으면 `next_cursor`가 옵니다. 나머지 조건이 **동일한** 쿼리에 `"cursor"`로 그대로 되돌려 보내면 다음 페이지를 받습니다. 파싱할 값이 아니라 불투명한 토큰입니다. 마지막 페이지에는 `next_cursor`가 없습니다.
- 페이지를 넘기는 동안 커서는 계속 유효합니다. 최신순 목록을 보던 중에 새 레코드가 기록돼도 남은 페이지가 밀리거나 중복되거나 빠지지 않습니다(새 레코드는 다음 번 새 쿼리에서 보입니다).
- 디코딩되지 않는 커서나 반대 `order`로 발급된 커서는 400을 받습니다.

렌더링·복호화 비용 없이 결과 건수만 알고 싶으면 같은 `LogQuery` 본문으로 `POST /v1/logs/count`를 호출하세요(`limit`, `cursor`, `order`는 무시됩니다).

```sh
curl -s -X POST localhost:7700/v1/logs/count \
  -H 'Authorization: Bearer aud1tor-t0ken' -H 'Content-Type: application/json' \
  -d '{ "method": "DELETE", "from_micros": 1780000000000000 }'
# {"count": 1843}
```

### 익스포트 (감사인 인계, SIEM 적재)

`POST /v1/logs/export`는 `/v1/logs/query`와 **같은 `LogQuery` 본문**을 받지만 응답은 `application/x-ndjson` — 한 줄에 `LogView` JSON 객체 하나 — 입니다. 감사인 인계와 로그 파이프라인이 대량 처리에 기대하는 포맷이죠.

```sh
curl -s -X POST localhost:7700/v1/logs/export \
  -H 'Authorization: Bearer aud1tor-t0ken' -H 'Content-Type: application/json' \
  -d '{ "from_micros": 1780000000000000 }' > audit-export.ndjson
```

권한(`query`)과 토큰별 동시성 상한은 쿼리와 같고, 차이는 응답 프레이밍뿐입니다. 필드 보호도 같은 키 경계를 따릅니다. RSA 개인 키 없는 서버는 보호 필드를 암호문으로 내보내고, 키 보유자가 하류에서 복호화합니다. 전체 스캔이므로 `from_micros`/`to_micros`로 범위를 잡으세요. 큰 스토어를 범위 없이 익스포트하는 것이 가장 묶어둘 가치가 있는 쿼리입니다.

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

모든 테이블은 해시 체인입니다(`sha256(직전 체인 값 || payload)`, 세그먼트 경계를 넘어도 이어집니다). 그래서 기록을 제자리에서 고치거나 세그먼트를 빼돌리고 바꿔치기하면 나중에라도 들통납니다. 임베디드에서는 `AuditStore::verify_integrity()`로 확인하는데, 서버는 같은 검사를 두 가지 방법으로 노출합니다.

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

체인이 끊긴 걸 찾았다면 그건 검증이 *제대로 일한* 겁니다. 그래서 응답은 여전히 200이고, 대신 `"ok": false`와 함께 끊긴 지점이 `problems`에 담겨 옵니다(검증은 첫 번째 끊김에서 멈추므로 항목은 많아야 하나입니다). 검증 자체를 돌리지 못했을 때만 에러 상태 코드가 나갑니다.

**주기적으로** — 설정에 `verify` 섹션을 넣으세요.

```json
"verify": { "interval_secs": 86400 }
```

시작할 때 한 번 돌고, 그 뒤로는 interval마다 한 번씩 돕니다. 체인 끊김을 찾거나 검증을 돌리지 못하면 `error` 레벨로 로그를 남기니, 알림은 그 로그 라인에 걸어 두면 됩니다. 섹션을 빼면 주기 검증만 꺼지고 엔드포인트는 그대로 동작합니다.

cron을 걸기 전에 알아둘 것 두 가지.

- 검증은 한 번에 하나만 돕니다. 엔드포인트와 주기 태스크가 같은 자리를 나눠 쓰므로, 누가 돌고 있는 동안 엔드포인트는 **409**를 주고 주기 태스크는 경고만 남기고 그 차례를 건너뜁니다.
- 검증은 모든 세그먼트를 **writer 스레드에서** 다시 읽습니다(체인이 스토어의 단일 writer 잠금 아래에 있기 때문입니다). 도는 동안 기록 요청은 디스크에 적히는 대신 파이프라인 큐에 쌓입니다. 보통 크기의 스토어라면 문제없지만, 아주 큰 스토어에 쓰기가 몰리는 환경이라면 한가한 시간대에 돌리거나, 검증 중 `POST /v1/logs`가 일부 503을 받을 수 있다고 보면 됩니다.

## 헬스 체크

`GET /v1/healthz`(토큰 불필요)는 `{"status": "ok"|"degraded"|"unhealthy", "reasons": [...]}`로 답합니다.

- **`unhealthy`** (HTTP **503**) — 이벤트가 디스크에 적히지 *못하고* 있다는 뜻입니다. writer 스레드가 죽었거나, 디스크 풀 래치가 걸려 있거나, 방금 스토어 루트에 시험 쓰기를 했는데 실패한 경우입니다.
- **`degraded`** (HTTP **200**) — 쓰기는 되지만 디스크 여유 공간이 `health` 기준 아래로 내려간 상태입니다. 일부러 200으로 둡니다. 아직 멀쩡히 기록 중인 인스턴스를 로드밸런서가 빼버리면 안 되니까요. 경고는 본문에 실려 있으니 모니터링이 거기에 알람을 걸면 됩니다.
- **`ok`** (HTTP **200**).

검사는 요청마다 실시간으로 돕니다. 파이프라인이 들고 있는 writer 생존 여부·디스크 풀 래치에 더해, 스토어 루트에 실제로 파일을 만들어 쓰고 fsync하고 지우는 시험 쓰기와 여유 공간 측정을 그 자리에서 수행합니다.

> 호환성 주의: v0.2 전에는 이 엔드포인트가 무조건 평문 `ok`를 돌려줬습니다. 본문 문자열을 비교하던 모니터링은 상태 코드나 JSON의 `status` 필드를 보도록 바꿔야 합니다.

## 메트릭

`GET /metrics`는 Prometheus 텍스트 포맷(v0.0.4)을 냅니다. 다른 운영용 엔드포인트와 마찬가지로 `administer` 권한 토큰 뒤에 있으니, Prometheus에게 전용 토큰을 하나 발급해 주세요.

```yaml
scrape_configs:
  - job_name: quipu
    authorization: { credentials: <token> }
    static_configs: [{ targets: ["quipu-host:7700"] }]
```

| 메트릭 | 타입 | 의미 |
|---|---|---|
| `quipu_queue_depth` | gauge | 큐에 들어갔지만 아직 writer가 집어가지 않은 이벤트 수 |
| `quipu_dlq_entries` | gauge | DLQ에 보관 중인 이벤트 수 |
| `quipu_writes_ok_total` | counter | 디스크에 안전하게 적힌 이벤트 수 |
| `quipu_write_retries_total` | counter | 실패 후 재시도된 쓰기 횟수 |
| `quipu_writes_parked_total` | counter | 재시도를 소진하고(또는 디스크 풀로) DLQ에 들어간 이벤트 수 |
| `quipu_events_lost_total` | counter | 스토어와 DLQ가 *둘 다* 실패한 이벤트 수. 폴백 훅만 남음 |
| `quipu_emit_rejected_total{reason}` | counter | 호출 시점에 거부된 emit: `queue_full` / `disk_full` |
| `quipu_write_latency_seconds` | histogram | 이벤트 하나를 안전하게 적는 데 걸린 시간(재시도 포함) |
| `quipu_store_bytes` | gauge | 스토어 루트 아래 디스크 사용량(모든 테이블 + DLQ) |
| `quipu_disk_free_bytes` / `quipu_disk_total_bytes` | gauge | 스토어 루트가 올라간 파일시스템의 여유/전체 |
| `quipu_writer_alive` | gauge | writer 스레드가 돌고 있으면 1 |
| `quipu_disk_full` | gauge | ENOSPC 래치가 걸려 있으면 1 |
| `quipu_disk_low` | gauge | 여유 공간이 경고 기준 아래면 1 |
| `quipu_verify_runs_total` | counter | 완료된 무결성 검증 횟수 |

알람 출발점: `quipu_writer_alive == 0`, `quipu_disk_full == 1`, `rate(quipu_events_lost_total[5m]) > 0`은 즉시 호출. `quipu_dlq_entries > 0`이 몇 분 이상 지속되거나, `quipu_disk_low == 1`, `quipu_queue_depth`가 계속 자라는 것은 경고로 두면 됩니다.

## 디스크가 가득 차면

스토어 루트가 올라간 볼륨이 차오를 때 무슨 일이 벌어지는지는, 우연이 아니라 정의된 동작입니다.

1. **사전 경고.** 파이프라인이 하우스키핑 주기(30초)마다 여유 공간을 잽니다. `health` 기준 아래로 내려가는 순간 `warn` 로그를 남기고, 폴백 훅에 한 번 알리며, `quipu_disk_low`를 1로, `/v1/healthz`를 `degraded`로 바꿉니다. 손을 쓸 시점은 바로 여기입니다 — 볼륨을 늘리거나, `retention_max_bytes`를 낮추거나, `POST /v1/admin/retention`을 돌리세요.
2. **ENOSPC.** "no space left on device"로 실패한 쓰기는 재시도·백오프 루프를 아예 건너뜁니다. 일시 장애가 아니라서 같은 바이트를 다시 써봐야 또 실패할 뿐이니까요. 이벤트는 곧장 DLQ로 가는데, DLQ도 보통 같은 가득 찬 디스크에 있어 함께 실패하므로 결국 폴백 훅과 `quipu_events_lost_total`에 도달합니다. 동시에 디스크 풀 래치가 걸립니다. `quipu_disk_full`이 1이 되고 `/v1/healthz`는 503으로 답합니다.
3. **빠른 거부(선택).** `health.reject_emit_when_disk_full`을 켜면 래치가 걸려 있는 동안 `POST /v1/logs`가 즉시 **507**로 답합니다. 어차피 폴백 훅으로 갈 이벤트를 큐에 쌓는 대신, 호출자가 대응할 수 있는 역압을 돌려주는 겁니다.
4. **복구는 자동입니다.** 쓰기가 다시 성공하거나, 하우스키핑이 여유 공간이 경고 기준 위로 돌아온 것을 확인하는 순간 래치가 풀립니다. 재시작도, 수동 리셋도 필요 없습니다.

예방 쪽 손잡이는 `retention_max_bytes`입니다. 볼륨 크기보다 작은 용량 예산을 주면, 보존 정책이 가장 오래된 봉인 세그먼트부터 지우면서 그 안에 머물게 해줍니다. `retention_days`와 같은 통세그먼트 unlink 방식이라 지운 뒤에도 무결성 검증은 그대로 통과합니다.

## 가용성과 복구

데몬은 설계상 단일 프로세스입니다([루트 README의 스코프 절](../../README.ko.md#분산-저장을-지원하지-않는-이유) 참고). 단일 writer라야 스토어를 파일 락 하나, 끊기지 않는 해시 체인 하나로 묶을 수 있습니다. 그래서 데몬은 가용성의 단일 장애점이 됩니다 — 데몬이 죽으면 호출자의 감사 기록이 멈춥니다 — 그러므로 이 프로젝트는 체인을 복제하는 대신 가용성을 *클라이언트*에서 해결합니다.

### 멱등 append

`POST /v1/logs`는 `Idempotency-Key` 헤더를 받습니다(1–128자 visible-ASCII 불투명 문자열, UUIDv4 형태 권장).

```sh
curl -s -X POST localhost:7700/v1/logs \
  -H 'Authorization: Bearer s3rv1ce-a-t0ken' \
  -H 'Idempotency-Key: 6f1e...c2' \
  -H 'Content-Type: application/json' -d '{ ... }'
```

서버는 최근 받은 키를 기억하고(설정 `"idempotency": { "window": 65536 }`, 메모리에 두며 재시작 시 잊음), 같은 키의 반복 요청에는 두 번째 이벤트를 기록하는 대신 `202 {"status":"duplicate"}`로 답합니다. 타임아웃은 "큐에 들어감"과 "유실됨"을 구분하지 못하므로, 이것이 클라이언트가 확인 못 한 요청을 안전하게 재시도하게 해줍니다.

윈도가 메모리에 있는 것은 의도된 설계입니다. 서버 재시작을 가로지른 재전송은 두 번 기록될 수 있지만, 두 사본 모두 클라이언트가 찍은 같은 `occurred_at`을 가지므로 사후에 중복임을 알 수 있습니다. 이 재시작 경우가 유일한 중복 경로입니다.

### 콜드 스탠바이 페일오버

장애 났거나 멈춘 노드는 라이브 페일오버가 아니라 콜드 스탠바이로 복구합니다. 페일오버 대상이 될 두 번째 writer가 없으니까요 — 그게 단일 체인 설계의 핵심입니다.

1. **액티브 노드를 정지시킵니다.** 아직 살아 있으면 `SIGINT`/`SIGTERM`으로 정상 종료(마지막 fsync)하거나, `POST /v1/admin/flush`로 액티브 세그먼트와 레지스트리 꼬리를 디스크에 내립니다. 봉인된 세그먼트는 이미 불변이라 언제든 안전하게 복사됩니다. 이 단계는 *액티브* 꼬리만 안정시킵니다.
2. **스토어 루트를 스탠바이 호스트로 복사합니다**(`rsync`, 스냅샷, 백업 복원 — 루트 README의 익스포트/백업 노트 참고). 봉인된 세그먼트는 절대 바뀌지 않으므로, 증분 복사는 액티브 꼬리만 옮깁니다.
3. **스탠바이에서 데몬을 띄웁니다**(복사한 루트 대상). open 시 `LOCK` 파일을 잡고, 비정상 종료가 남긴 찢어진 꼬리를 잘라낸 뒤(CRC 프레이밍이라 반쯤 쓰인 레코드는 오독되지 않고 버려집니다) 다시 쓰기 가능해집니다.
4. **클라이언트를 스탠바이로 돌립니다**(DNS/로드밸런서). `quipu-client`를 쓰는 클라이언트는 그 공백 동안 이벤트를 로컬 스풀에 들고 있다가 다음 `drain_spool`에 재생합니다. 멱등 키 덕에 옛 노드가 이미 받은 것을 재생해도 no-op이 됩니다.

재시작 시간은 스토어 전체가 아니라 **액티브** 세그먼트 크기 + 레지스트리 재생에 비례합니다. 봉인된 세그먼트는 open 때 다시 스캔되지 않습니다. `max_segment_bytes`를 적당히 작게 두면 그 꼬리, 따라서 페일오버가 빨라집니다.

### SIEM 포워딩

`sink` 섹션을 추가하면 디스크에 안전하게 적힌 이벤트를 syslog 수집기(RFC 5424/UDP)로 미러링합니다.

```json
"sink": { "syslog_udp": "10.0.0.5:514", "app_name": "quipu-server", "queue_capacity": 16384 }
```

받아들인 이벤트마다 syslog 한 줄이 되고, 메시지는 컴팩트한 JSON 요약입니다 — log id, actor, method, url, target id, 커스텀 컬럼 키. 이벤트 **`content`는 포워딩하지 않습니다.** 크거나 보호 값을 담을 수 있고, 스토어가 시스템 오브 레코드이기 때문입니다. SIEM은 감사 추적의 골격만 받습니다.

미러는 **베스트에포트이며 절대 쓰기를 막지 않습니다.** 전용 스레드가 소켓을 소유하고, writer 스레드는 논블로킹 enqueue만 하며, 백로그가 가득 차면 영속화를 멈추는 대신 줄을 버립니다(카운트하고 드물게 로깅). 성공 시에만 발동하니, DLQ에 박힌 이벤트는 미러링되지 않습니다.

syslog가 데몬이 기본 제공하는 유일한 sink입니다(추가 의존성 없음). webhook/Kafka/기타 sink는 같은 모양 — `quipu_middleware::SinkFn` 클로저 — 이라, 파이프라인을 직접 굴리는 임베디드 사용자가 끼울 수 있습니다.

## v1에서 의도적으로 둔 제약

- 스토어도 하나, 테넌트도 하나입니다. 토큰이 가르는 것은 할 수 있는 일(emit/query/admin)이지 볼 수 있는 데이터가 아니라서, 모든 reader가 모든 로그를 봅니다. 테넌트 격리는 테넌트마다 스토어 루트를 따로 두는 일이라 다음 과제로 남겨뒀습니다.
- 레퍼런스 클라이언트([`quipu-client`](../quipu-client/README.ko.md))는 재전송/스풀 프로토콜만 담고 전송 계층은 담지 않습니다. 위 API는 어떤 HTTP 클라이언트로도 부를 수 있을 만큼 작습니다. gRPC가 아니라 JSON을 고른 이유이기도 합니다.
