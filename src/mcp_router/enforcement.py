import jwt
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from .auth_context import reset_claims, set_claims
from .settings import Settings
from .tokens import TokenClaims, TokenError, verify_access_token


class TokenEnforcementMiddleware:
    """Rejects unauthenticated MCP traffic before it reaches the tool layer.

    Validation is local: key set and revocation list are cached, so a request never
    waits on the authorization server.
    """

    def __init__(
        self,
        app,
        *,
        settings: Settings,
        key_set,
        revocations,
        audit=None,
        exempt_prefixes: tuple[str, ...] = ("/approvals/",),
    ) -> None:
        self.app = app
        self.settings = settings
        self.key_set = key_set
        self.revocations = revocations
        self.audit = audit
        self.exempt_prefixes = exempt_prefixes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or str(scope.get("path", "")).startswith(self.exempt_prefixes):
            await self.app(scope, receive, send)
            return

        token, header_error = self._extract_token(scope)
        if token is None:
            await self._deny(scope, receive, send, 401, header_error)
            return

        try:
            claims = await self._authenticate(token)
        except TokenError as exc:
            await self._deny(scope, receive, send, 401, exc.code)
            return

        scope.setdefault("state", {})["claims"] = claims
        self._record("allow", claims=claims, path=scope.get("path"))

        token = set_claims(claims)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_claims(token)

    def _extract_token(self, scope) -> tuple[str | None, str]:
        header = Headers(scope=scope).get("authorization")
        if not header:
            return None, "missing_token"
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None, "invalid_authorization_header"
        return token, ""

    async def _authenticate(self, token: str) -> TokenClaims:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise TokenError("invalid_token", "unreadable header") from exc

        if not kid:
            raise TokenError("invalid_token", "missing kid")

        public_key = await self.key_set.public_key(kid)
        if public_key is None:
            raise TokenError("invalid_token", "unknown signing key")

        claims = verify_access_token(
            token,
            public_key,
            issuer=self.settings.issuer_url,
            audience=self.settings.resource_audience,
            skew_seconds=self.settings.clock_skew_seconds,
        )

        if await self.revocations.is_revoked(claims.jti):
            raise TokenError("token_revoked")

        return claims

    async def _deny(self, scope, receive, send, status: int, code: str) -> None:
        self._record("deny", code=code, path=scope.get("path"))
        response = JSONResponse({"error": code}, status_code=status)
        response.headers["WWW-Authenticate"] = f'Bearer error="{code}"'
        await response(scope, receive, send)

    def _record(self, decision: str, *, code: str | None = None, claims=None, path=None) -> None:
        if self.audit is None:
            return
        self.audit(
            event="token_validation",
            decision=decision,
            reason=code,
            subject=getattr(claims, "sub", None),
            path=path,
        )
