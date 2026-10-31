from fastmcp.server.middleware import Middleware

from .auth_context import current_claims
from .registry import ToolRegistry


class DisclosureMiddleware(Middleware):
    """Tools the caller cannot use are not advertised in tools/list."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        claims = current_claims()
        scopes = claims.scopes() if claims else set()
        extended = "mcp:tools:extended" in scopes
        allowed = {spec.name for spec in self.registry.visible_to(scopes, extended)}
        return [tool for tool in tools if tool.name in allowed]
