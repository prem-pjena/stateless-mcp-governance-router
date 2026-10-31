import json

from starlette.responses import JSONResponse

from .auth_context import current_claims
from .registry import ToolRegistry


class ScopeGuardMiddleware:
    """Rejects a tools/call whose token does not carry the tool's scope.

    The scope decision is made here (HTTP 403) rather than inside the tool, so an
    unauthorized call never reaches tool code at all.
    """

    def __init__(self, app, *, registry: ToolRegistry, mcp_path: str = "/mcp", audit=None) -> None:
        self.app = app
        self.registry = registry
        self.mcp_path = mcp_path
        self.audit = audit

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        if not str(scope.get("path", "")).startswith(self.mcp_path):
            await self.app(scope, receive, send)
            return

        body, replay = await _buffer_body(receive)
        tool_name = _tool_call_name(body)

        if tool_name is not None:
            spec = self.registry.get(tool_name)
            claims = current_claims()
            scopes = claims.scopes() if claims else set()
            if spec is not None and spec.scope not in scopes and "mcp:admin" not in scopes:
                if self.audit is not None:
                    self.audit(
                        "scope_denied",
                        tool=tool_name,
                        required=spec.scope,
                        subject=claims.sub if claims else None,
                    )
                response = JSONResponse(
                    {"error": "insufficient_scope", "tool": tool_name, "required": spec.scope},
                    status_code=403,
                )
                await response(scope, receive, send)
                return

        await self.app(scope, replay, send)


async def _buffer_body(receive) -> tuple[bytes, callable]:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        body = message.get("body", b"")
        if body:
            chunks.append(body)
        if not message.get("more_body"):
            break

    raw = b"".join(chunks)
    replayed = False

    async def replay():
        nonlocal replayed
        if replayed:
            return await receive()
        replayed = True
        return {"type": "http.request", "body": raw, "more_body": False}

    return raw, replay


def _tool_call_name(raw: bytes) -> str | None:
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None

    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return None

    params = payload.get("params")
    if not isinstance(params, dict):
        return None

    name = params.get("name")
    return name if isinstance(name, str) else None
