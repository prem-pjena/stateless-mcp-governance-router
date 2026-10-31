import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import keys
from .clients import load_clients
from .rate_limit import TokenBucketLimiter
from .replay import build_replay_store
from .settings import Settings, get_settings
from .tokens import (
    ASSERTION_TYPE,
    TokenError,
    mint_access_token,
    verify_client_assertion,
)


class ReplayStore:
    """In-process jti store. Kept for backwards compatibility; prefer build_replay_store."""

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._seen: dict[str, int] = {}

    def check_and_store(self, jti: str) -> bool:
        now = int(time.time())
        self._prune(now)
        if jti in self._seen:
            return False
        self._seen[jti] = now + self._ttl
        return True

    def _prune(self, now: int) -> None:
        expired = [jti for jti, exp in self._seen.items() if exp <= now]
        for jti in expired:
            del self._seen[jti]


class Revocations:
    def __init__(self) -> None:
        self._entries: dict[str, int] = {}

    def add(self, jti: str, expires_at: int) -> None:
        self._entries[jti] = expires_at

    def active(self) -> list[dict]:
        now = int(time.time())
        for jti in [j for j, exp in self._entries.items() if exp <= now]:
            del self._entries[jti]
        return [{"jti": jti, "exp": exp} for jti, exp in self._entries.items()]


def _error(status: int, code: str, description: str | None = None) -> JSONResponse:
    body = {"error": code}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status)


def build_app(settings: Settings | None = None) -> Starlette:
    settings = settings or get_settings()
    signing_key = keys.load_or_create_key(settings.signing_key_path)
    kid = keys.key_id(keys.public_pem(signing_key))
    clients = load_clients(settings.clients_file)
    replays = build_replay_store(settings)
    limiter = TokenBucketLimiter(settings.token_rate_limit_per_minute)
    revocations = Revocations()

    async def metadata(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "issuer": settings.issuer_url,
                "token_endpoint": settings.token_endpoint,
                "revocation_endpoint": f"{settings.issuer_url}/revoke",
                "jwks_uri": settings.jwks_uri,
                "grant_types_supported": ["client_credentials"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["EdDSA"],
                "scopes_supported": sorted({scope for client in clients.values() for scope in client.scopes}),
            }
        )

    async def jwks(request: Request) -> JSONResponse:
        return JSONResponse({"keys": [keys.public_jwk(signing_key, kid)]})

    async def token(request: Request) -> JSONResponse:
        form = await request.form()
        grant_type = form.get("grant_type")
        assertion_type = form.get("client_assertion_type")
        assertion = form.get("client_assertion")
        client_id = form.get("client_id")

        if grant_type != "client_credentials":
            return _error(400, "unsupported_grant_type")
        if assertion_type != ASSERTION_TYPE:
            return _error(400, "invalid_request", "client_assertion_type must be jwt-bearer")
        if not assertion or not client_id:
            return _error(400, "invalid_request", "client_id and client_assertion are required")

        client = clients.get(str(client_id))
        if client is None:
            return _error(401, "invalid_client")

        allowed, retry_after = limiter.allow(str(client_id))
        if not allowed:
            limit_error = _error(429, "too_many_requests", "token endpoint rate limit exceeded")
            limit_error.headers["Retry-After"] = str(int(retry_after) + 1)
            return limit_error

        try:
            claims = verify_client_assertion(
                str(assertion),
                keys.load_public_key(client.public_key_pem),
                client_id=str(client_id),
                audience=settings.token_endpoint,
                max_ttl_seconds=settings.assertion_max_ttl_seconds,
                skew_seconds=settings.clock_skew_seconds,
            )
        except TokenError as exc:
            return _error(401, exc.code, exc.detail)

        if not await replays.check_and_store(str(claims["jti"]), settings.assertion_max_ttl_seconds):
            return _error(400, "replay_detected")

        requested = {scope for scope in str(form.get("scope", "")).split() if scope}
        if not requested.issubset(client.scopes):
            return _error(400, "invalid_scope", "requested scope exceeds client grant")

        scope = " ".join(sorted(requested)) if requested else " ".join(sorted(client.scopes))
        access_token = mint_access_token(
            issuer=settings.issuer_url,
            subject=str(client_id),
            audience=settings.resource_audience,
            scope=scope,
            ttl_seconds=settings.access_token_ttl_seconds,
            signing_key=signing_key,
            kid=kid,
            tenant_id=client.tenant_id,
        )
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": settings.access_token_ttl_seconds,
                "scope": scope,
            }
        )

    async def revoke(request: Request) -> JSONResponse:
        form = await request.form()
        client_id = form.get("client_id")
        assertion = form.get("client_assertion")
        jti = form.get("jti")
        if not client_id or not assertion or not jti:
            return _error(400, "invalid_request")

        client = clients.get(str(client_id))
        if client is None:
            return _error(401, "invalid_client")

        try:
            verify_client_assertion(
                str(assertion),
                keys.load_public_key(client.public_key_pem),
                client_id=str(client_id),
                audience=settings.token_endpoint,
                max_ttl_seconds=settings.assertion_max_ttl_seconds,
                skew_seconds=settings.clock_skew_seconds,
            )
        except TokenError as exc:
            return _error(401, exc.code, exc.detail)

        revocations.add(str(jti), int(time.time()) + settings.access_token_ttl_seconds)
        return JSONResponse({"revoked": True})

    async def revoked(request: Request) -> JSONResponse:
        return JSONResponse({"revoked": revocations.active()})

    return Starlette(
        routes=[
            Route("/.well-known/oauth-authorization-server", metadata),
            Route("/.well-known/jwks.json", jwks),
            Route("/token", token, methods=["POST"]),
            Route("/revoke", revoke, methods=["POST"]),
            Route("/revoked", revoked),
        ]
    )


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(build_app(settings), host=settings.as_host, port=settings.as_port)


if __name__ == "__main__":
    main()
