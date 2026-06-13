# quipu-mcp

English | [한국어](README.ko.md)

A [Model Context Protocol](https://modelcontextprotocol.io) server that puts a [Quipu-Log](../../README.md) audit store in front of an LLM agent — an **AI auditor**. The agent takes questions in natural language ("did anything odd touch the billing records last night?", "has this log been tampered with?") and answers by searching the log, walking entity history, and verifying the store's tamper-evidence chains.

## Architecture: an HTTP client, not an embedded store

`quipu-mcp` talks to `quipu-server` over the ordinary token-authenticated HTTP API. It does **not** embed `quipu-core` and open the store directly. Three reasons:

- **The store is single-writer.** `quipu-server` holds a file lock on the store root. An embedded MCP process can't open that store while the daemon is running — which is exactly the "AI auditor watching the live system" case this is built for. HTTP sidesteps the lock.
- **It reuses the existing trust boundary.** Authentication, role-based scopes, the per-token query-concurrency cap, and the key boundary (a server started without the RSA private key returns protected fields as ciphertext) all live in `quipu-server`. The agent gets exactly what its token's role grants. There's no new security surface to get right here.
- **The agent's reads are audited through the same path.** Every tool call is an HTTP query or verify. When read meta-auditing is on, the agent's own lookups land in the ledger like any other reader's — "the AI's access is itself audited" comes for free.

```
LLM agent ──MCP/stdio──> quipu-mcp ──HTTP(+bearer)──> quipu-server ──> store
```

## Scopes are roles

There's no separate scope system. An MCP token's "scope" is the **role** it maps to in the server config, and the role's grants decide what the agent can do. Two roles cover the auditor cases:

| intended scope | server role grants | tools it unlocks |
|---|---|---|
| read-only auditor | `["query"]` | `query_logs`, `get_entity_history` |
| auditor + integrity | `["query", "administer"]` | + `verify_store_integrity` |

Nothing grants `emit`: the agent can read and verify the ledger, never write to it. (`verify` needs `administer` only because integrity verification is an admin endpoint server-side; it's still read-only in effect.)

## Issuing a token

The server stores tokens hashed and can expire them. `quipu-mcp` mints one and prints the config line:

```sh
quipu-mcp issue-token audit-reader            # non-expiring
quipu-mcp issue-token audit-reader 1924905600 # expires at that unix time
```

```
token (give to the client, store nowhere else):
  a2b6613c...e993877
add under auth.tokens in the server config:
  "sha256:9b774694...0bff79": "audit-reader"
then grant the role its scope under auth.grants, e.g.
  "audit-reader": ["query"]   (add "administer" to allow verify_store_integrity)
```

The token is shown once. The config keeps only its `sha256:` hash, so the config file isn't itself a credential, and a running server picks up the new token on `SIGHUP` — no restart, no downtime.

## Running it

`serve` reads its upstream from the environment (so the token stays out of argv and any MCP client's process table) and speaks MCP on stdio:

```sh
QUIPU_SERVER_ADDR=127.0.0.1:7700 QUIPU_MCP_TOKEN=<token> quipu-mcp serve
```

Wire it into an MCP client (e.g. Claude Desktop / Claude Code) as a stdio server:

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

The transport is plaintext HTTP by design. Run `quipu-mcp` co-located with `quipu-server` — same host or trusted segment — against its plain-HTTP listener. For a remote leg, put a TLS-terminating sidecar in front rather than teaching this client TLS. The point is to keep the agent-facing binary tiny and (almost) dependency-free.

## The tools

| tool | arguments | what it answers |
|---|---|---|
| `query_logs` | `{ "query": <LogQuery> }` | "who did what to which entity, when" — the full search surface (time range, actor, method, url, target attribute filters). |
| `get_entity_history` | `{ "entity_type", "entity_id" }` | "how did this entity change over time" — every recorded version, oldest first. |
| `verify_store_integrity` | `{}` | "has the log been altered" — runs the hash-chain verification; `ok:false` names the first break. |

Tool failures come back as normal results with `isError: true` and a readable message (e.g. "the audit server is unreachable, try again"), so the agent can reason about them instead of crashing the session.

## A demo scenario

With the server seeded and the MCP server wired into Claude, the auditor conversation looks like this:

> **You:** Has anyone accessed account `acct-9` in a way that looks unusual in the last day?
>
> *(the agent calls `query_logs` with a `from_micros` ~24h ago and a target filter on `account`/`acct-9`, reads the returned `LogView`s, and summarizes the actors, methods, and times — flagging, say, a burst of reads from one actor.)*
>
> **You:** Walk me through how `acct-9` itself changed.
>
> *(the agent calls `get_entity_history` and narrates the version timeline.)*
>
> **You:** And can we trust this log hasn't been edited?
>
> *(the agent calls `verify_store_integrity` and reports `ok:true` with the segment and record counts, or names the break.)*

Two patterns this enables: **continuous anomaly triage** (the agent periodically asking "anything unusual?") and **forensic tracing** (an integrity check plus a change-history walk when something looks off).
