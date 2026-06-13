# quipu-mcp

[English](README.md) | 한국어

[Quipu-Log](../../README.ko.md) 감사 스토어를 LLM 에이전트 앞에 놓는 [Model Context Protocol](https://modelcontextprotocol.io) 서버 — **AI 감사관**입니다. 에이전트는 "어젯밤 결제 기록을 건드린 이상한 접근이 있었나?", "이 로그가 위변조됐나?" 같은 질문을 자연어로 받고, 로그를 검색하고 엔티티 이력을 훑고 스토어의 위변조 방지 체인을 검증해 답합니다.

## 아키텍처: 임베디드가 아니라 HTTP 클라이언트

`quipu-mcp`는 `quipu-server`에 평범한 토큰 인증 HTTP API로 말합니다. `quipu-core`를 임베드해 스토어를 직접 열지 **않습니다**. 이유는 셋입니다.

- **스토어는 단일 writer입니다.** `quipu-server`가 스토어 루트에 파일 락을 잡습니다. 데몬이 도는 동안 임베디드 MCP 프로세스는 같은 스토어를 열 수 없습니다 — 그게 바로 이 도구가 노리는 "라이브 시스템을 지켜보는 AI 감사관" 상황입니다. HTTP는 락을 우회합니다.
- **이미 있는 신뢰 경계를 재사용합니다.** 인증, 역할 기반 스코프, 토큰별 쿼리 동시성 상한, 키 경계(RSA 개인 키 없이 띄운 서버는 보호 필드를 암호문으로 반환)가 모두 `quipu-server`에 삽니다. 에이전트는 토큰 역할이 허용하는 만큼만 얻습니다. 여기서 새로 지킬 보안 표면이 없습니다.
- **에이전트의 조회도 같은 경로로 감사됩니다.** 모든 tool 호출이 HTTP 쿼리나 검증입니다. 조회 메타 감사가 켜져 있으면 에이전트의 조회도 다른 reader처럼 원장에 박힙니다. "AI의 접근 자체가 감사된다"가 공짜로 따라옵니다.

```
LLM 에이전트 ──MCP/stdio──> quipu-mcp ──HTTP(+bearer)──> quipu-server ──> 스토어
```

## 스코프 = 역할

별도 스코프 시스템은 없습니다. MCP 토큰의 "스코프"는 서버 설정에서 매핑된 **역할**이고, 역할의 grant가 에이전트가 할 수 있는 일을 정합니다. 감사관 유스케이스는 두 역할로 충분합니다.

| 의도한 스코프 | 서버 역할 grant | 열리는 tool |
|---|---|---|
| 읽기 전용 감사관 | `["query"]` | `query_logs`, `get_entity_history` |
| 감사관 + 무결성 | `["query", "administer"]` | + `verify_store_integrity` |

`emit`은 아무에게도 주지 않습니다. 에이전트는 원장을 읽고 검증할 뿐 쓰지 못합니다. (`verify`가 `administer`를 요구하는 건 서버 측에서 무결성 검증이 admin 엔드포인트이기 때문이고, 효과는 여전히 읽기 전용입니다.)

## 토큰 발급

서버는 토큰을 해시로 저장하고 만료시킬 수 있습니다. `quipu-mcp`가 하나 발급하고 설정 줄을 출력합니다.

```sh
quipu-mcp issue-token audit-reader            # 만료 없음
quipu-mcp issue-token audit-reader 1924905600 # 해당 unix 시각에 만료
```

```
token (give to the client, store nowhere else):
  a2b6613c...e993877
add under auth.tokens in the server config:
  "sha256:9b774694...0bff79": "audit-reader"
then grant the role its scope under auth.grants, e.g.
  "audit-reader": ["query"]   (add "administer" to allow verify_store_integrity)
```

토큰은 한 번만 표시됩니다. 설정에는 `sha256:` 해시만 남으므로 설정 파일 자체가 자격증명이 아니고, 도는 서버는 `SIGHUP`에 새 토큰을 집어듭니다 — 재시작도 다운타임도 없습니다.

## 실행

`serve`는 업스트림을 환경변수에서 읽고(토큰이 argv나 MCP 클라이언트 프로세스 테이블에 남지 않도록) stdio로 MCP를 말합니다.

```sh
QUIPU_SERVER_ADDR=127.0.0.1:7700 QUIPU_MCP_TOKEN=<token> quipu-mcp serve
```

MCP 클라이언트(예: Claude Desktop / Claude Code)에 stdio 서버로 끼웁니다.

```json
{
  "mcpServers": {
    "quipu-audit": {
      "command": "quipu-mcp",
      "args": ["serve"],
      "env": { "QUIPU_SERVER_ADDR": "127.0.0.1:7700", "QUIPU_MCP_TOKEN": "<token>" }
    }
  }
}
```

전송은 설계상 평문 HTTP입니다. `quipu-mcp`를 `quipu-server`와 같은 호스트(또는 신뢰 구간)에 두고 그 평문 HTTP 리스너에 붙이세요. 원격 구간이면 이 클라이언트에 TLS를 가르치는 대신 TLS 종단 사이드카를 앞에 둡니다. 에이전트가 마주하는 바이너리를 작고 (거의) 의존성 없게 유지하는 게 핵심입니다.

## tool

| tool | 인자 | 답하는 질문 |
|---|---|---|
| `query_logs` | `{ "query": <LogQuery> }` | "누가 어떤 엔티티에 무엇을 언제 했나" — 전체 검색 표면(시간 범위, actor, method, url, target 속성 필터). |
| `get_entity_history` | `{ "entity_type", "entity_id" }` | "이 엔티티가 시간에 따라 어떻게 바뀌었나" — 기록된 모든 버전, 오래된 것부터. |
| `verify_store_integrity` | `{}` | "로그가 변조됐나" — 해시 체인 검증 실행. `ok:false`면 첫 균열을 짚는다. |

tool 실패는 `isError: true`와 읽을 수 있는 메시지를 단 일반 결과로 돌아옵니다(예: "감사 서버에 닿지 않음, 재시도"). 그래서 에이전트는 세션을 죽이는 대신 그 상황을 추론할 수 있습니다.

## 데모 시나리오

서버에 데이터를 넣고 MCP 서버를 Claude에 물리면, 감사관 대화는 이렇게 흐릅니다.

> **사용자:** 지난 하루 동안 `acct-9` 계정에 이상해 보이는 접근이 있었어?
>
> *(에이전트가 ~24시간 전 `from_micros`와 `account`/`acct-9` target 필터로 `query_logs`를 호출, 돌아온 `LogView`를 읽고 actor·method·시각을 요약 — 예컨대 한 actor의 연속 조회 폭주를 짚는다.)*
>
> **사용자:** `acct-9` 자체가 어떻게 바뀌었는지 보여줘.
>
> *(에이전트가 `get_entity_history`를 호출해 버전 타임라인을 설명한다.)*
>
> **사용자:** 이 로그가 편집되지 않았다고 믿을 수 있어?
>
> *(에이전트가 `verify_store_integrity`를 호출해 세그먼트·레코드 수와 함께 `ok:true`를 보고하거나 균열을 짚는다.)*

이게 가능케 하는 두 패턴: **상시 이상 징후 분류**(에이전트가 주기적으로 "이상한 거 있어?"를 묻는 것)와 **포렌식 추적**(뭔가 이상할 때 무결성 검증 + 변경 이력 훑기).
