import time
import uuid

import jwt
import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_router import keys
from mcp_router.enforcement import TokenEnforcementMiddleware
from mcp_router.jwks_cache import StaticKeySet
from mcp_router.revocation_cache import RevocationCache
from mcp_router.settings import Settings

ISSUER = "http://issuer.test"
AUDIENCE = "mcp://router"
KID = "test-key"


class FakeRevocations(RevocationCache):
    def __init__(self, revoked: set[str] | None = None) -> None:
        super().__init__("http://unused/revoked", ttl_seconds=60)
        self._revoked = set(revoked or set())
        self._fetched_at = time.monotonic()

    async def refresh(self) -> None:
        self.fetches += 1
        self._fetched_at = time.monotonic()


@pytest.fixture
def ctx(tmp_path):
    signing_key = keys.load_or_create_key(tmp_path / "as_key.pem")

    settings = Settings(
        issuer_url=ISSUER,
        resource_audience=AUDIENCE,
        keys_dir=tmp_path,
        clock_skew_seconds=5,
    )

    async def echo(request):
        claims = request.scope.get("state", {}).get("claims")
        return JSONResponse({"sub": claims.sub if claims else None, "scope": claims.scope if claims else None})

    revocations = FakeRevocations()

    app = Starlette(
        routes=[Route("/mcp", echo, methods=["POST"])],
        middleware=[
            Middleware(
                TokenEnforcementMiddleware,
                settings=settings,
                key_set=StaticKeySet({KID: signing_key.public_key()}),
                revocations=revocations,
            )
        ],
    )
    return settings, signing_key, revocations, TestClient(app)


def make_token(signing_key, *, aud=AUDIENCE, iss=ISSUER, ttl=900, kid=KID, jti=None, algorithm="EdDSA"):
    now = int(time.time())
    payload = {
        "iss": iss,
        "sub": "client-alpha",
        "aud": aud,
        "scope": "mcp:documents:read",
        "iat": now,
        "exp": now + ttl,
        "jti": jti or uuid.uuid4().hex,
    }
    return jwt.encode(payload, signing_key, algorithm=algorithm, headers={"kid": kid} if kid else {})


def call(client, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/mcp", json={}, headers=headers)


def test_missing_token_is_rejected(ctx):
    _, _, _, client = ctx
    response = call(client)
    assert response.status_code == 401
    assert response.json()["error"] == "missing_token"
    assert "Bearer" in response.headers["www-authenticate"]


def test_non_bearer_scheme_is_rejected(ctx):
    _, _, _, client = ctx
    response = client.post("/mcp", json={}, headers={"Authorization": "Basic abc"})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_authorization_header"


def test_malformed_token_is_rejected(ctx):
    _, _, _, client = ctx
    assert call(client, "not-a-jwt").json()["error"] == "invalid_token"


def test_unknown_kid_is_rejected(ctx):
    _, signing_key, _, client = ctx
    response = call(client, make_token(signing_key, kid="rotated-out"))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


def test_wrong_audience_is_rejected(ctx):
    _, signing_key, _, client = ctx
    response = call(client, make_token(signing_key, aud="mcp://another-service"))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_audience"


def test_wrong_issuer_is_rejected(ctx):
    _, signing_key, _, client = ctx
    response = call(client, make_token(signing_key, iss="http://attacker.test"))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_issuer"


def test_expired_token_is_rejected(ctx):
    _, signing_key, _, client = ctx
    response = call(client, make_token(signing_key, ttl=-60))
    assert response.status_code == 401
    assert response.json()["error"] == "token_expired"


def test_token_within_clock_skew_is_accepted(ctx):
    _, signing_key, _, client = ctx
    response = call(client, make_token(signing_key, ttl=-3))
    assert response.status_code == 200
    assert response.json()["sub"] == "client-alpha"


def test_revoked_token_is_rejected(ctx):
    _, signing_key, revocations, client = ctx
    jti = uuid.uuid4().hex
    revocations._revoked = {jti}

    response = call(client, make_token(signing_key, jti=jti))
    assert response.status_code == 401
    assert response.json()["error"] == "token_revoked"


def test_valid_token_reaches_the_app(ctx):
    _, signing_key, _, client = ctx
    response = call(client, make_token(signing_key))
    assert response.status_code == 200
    assert response.json() == {"sub": "client-alpha", "scope": "mcp:documents:read"}


def test_revocation_lookup_does_not_hit_the_issuer_per_request(ctx):
    _, signing_key, revocations, client = ctx
    token = make_token(signing_key)

    for _ in range(25):
        assert call(client, token).status_code == 200

    assert revocations.fetches <= 1


def test_mcp_endpoint_requires_a_token(tmp_path):
    from mcp_router.server import build_app

    settings = Settings(
        keys_dir=tmp_path,
        issuer_url="http://127.0.0.1:9",
        resource_audience=AUDIENCE,
        allowed_hosts=["testserver"],
    )
    client = TestClient(build_app(settings))

    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 401
