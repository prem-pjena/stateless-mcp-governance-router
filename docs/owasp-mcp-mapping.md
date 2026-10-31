# OWASP MCP Top-10 — Control Mapping

Scope: the current implementation of the Stateless MCP Governance Router. Status values are
`implemented`, `verified` (exercised by an automated test or the harness), or `gap`.

| ID | Risk | Control in this project | Status |
|----|------|-------------------------|--------|
| MCP01 | Token / secret exposure | Private keys are generated locally, gitignored, `chmod 600`; no shared client secrets exist (private_key_jwt only); error bodies never echo claims or stack traces | implemented, verified |
| MCP02 | Scope creep / over-permissioned tokens | Tokens are scoped per namespace (`mcp:<namespace>:read\|write`); the authorization server rejects any requested scope beyond the client grant | implemented, verified |
| MCP03 | Tool poisoning | Tool definitions live in code and are validated by the registry (strict Pydantic models, namespace/scope conformance, schema version required). Tool descriptions are not fetched from remote sources | implemented, verified |
| MCP04 | Supply chain | Small dependency set (fastmcp, pydantic, PyJWT, cryptography, starlette); versions pinned in `pyproject.toml` | implemented |
| MCP05 | Command injection / unsafe tool definitions | Registry rejects untyped or `Any`/`dict` inputs, non-Pydantic models, missing schema versions; no shell execution exists in any tool | implemented, verified |
| MCP06 | Prompt injection via tool output | Out of scope for this layer: the router does not interpret tool output as instructions. Documented as a gap for the agent layer | gap (documented) |
| MCP07 | Insufficient authentication / authorization | OAuth 2.1 authorization server, RFC 7523 private_key_jwt (EdDSA), no DCR, short-lived access tokens, 5-second clock-skew tolerance, cached revocation, hard audience binding, per-tool scope enforcement at HTTP level (403) | implemented, verified |
| MCP08 | Lack of audit | Append-only JSONL audit sink records token decisions, scope denials, approval lifecycle; write failures are recorded, never swallowed | implemented, verified |
| MCP09 | Shadow MCP servers | The registry is the only way to expose a tool; anything not registered cannot be listed or invoked | implemented, verified |
| MCP10 | Context / state leakage | The server is stateless (no session state); pending approvals persist in SQLite and are single-use; request state is carried in the token | implemented, verified |

## Agentic-AI (ASI) overlap

| ID | Risk | Control | Status |
|----|------|---------|--------|
| ASI01 | Goal hijacking | Tokens bind to a namespace and audience, so a hijacked planner cannot reach tools outside its grant | partially covered |
| ASI02 | Tool misuse | High-risk tools require a signed, single-use human approval before execution | implemented, verified |
| ASI05 | Unexpected code execution | No shell, no eval, no dynamic imports; filesystem tools are confined by realpath-checked roots | implemented, verified |
| ASI06 | Memory poisoning | No cross-request memory exists on the server side | not applicable |
| ASI08 | Cascading failures | Deny-by-default guards; failures return deterministic errors instead of falling through | implemented, verified |

## Known gaps

- **Revocation latency:** revocation is cached for one TTL window, so a revoked token stays usable for at most
  that window. This is a deliberate tradeoff to avoid a per-request call to the authorization server.
- **MCP06 (prompt injection through tool output)** is not addressed here; the router does not process content,
  so this belongs to the consuming agent. It is listed in the P3 scope.
- **Rate limiting is per process:** the token-endpoint bucket is in-process, so N replicas allow roughly N×
  the configured rate. Replay protection is shared (Redis) but the limiter is not yet.
- **Audit sink is a local JSONL file**, which is fine for a single host but is not a durable central store.
