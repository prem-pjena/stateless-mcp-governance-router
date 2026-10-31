from starlette.datastructures import Headers
from starlette.responses import JSONResponse

MCP_PATH = "/mcp"


class IngressGuardMiddleware:
    """Cheap checks that run before anything else on the MCP path.

    Host and Origin are matched against explicit allowlists. An empty allowlist
    denies everything: a misconfigured deployment should fail closed, not open.
    """

    def __init__(
        self,
        app,
        *,
        allowed_hosts: list[str],
        allowed_origins: list[str],
        mcp_path: str = MCP_PATH,
    ) -> None:
        self.app = app
        self.allowed_hosts = set(allowed_hosts)
        self.allowed_origins = set(allowed_origins)
        self.mcp_path = mcp_path

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not str(scope.get("path", "")).startswith(self.mcp_path):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)

        host = headers.get("host")
        if host is None or host not in self.allowed_hosts:
            await self._deny(scope, receive, send, 400, "host")
            return

        origin = headers.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            await self._deny(scope, receive, send, 400, "origin")
            return

        if origin is None and (headers.get("user-agent") or "").startswith("Mozilla"):
            await self._deny(scope, receive, send, 400, "missing_origin")
            return

        if scope.get("method") != "POST":
            response = JSONResponse({"error": "MethodNotAllowed"}, status_code=405)
            response.headers["Allow"] = "POST"
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

    async def _deny(self, scope, receive, send, status: int, detail: str) -> None:
        response = JSONResponse({"error": "HeaderMismatch", "detail": detail}, status_code=status)
        await response(scope, receive, send)
