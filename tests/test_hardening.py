import time
import uuid

import jwt
import pytest
from starlette.testclient import TestClient

from mcp_router import keys
from mcp_router.authorization_server import build_app
from mcp_router.clients import write_clients
from mcp_router.rate_limit import TokenBucketLimiter
from mcp_router.replay import InProcessReplayStore, RedisReplayStore, build_replay_store
from mcp_router.settings import Settings

CLIENT_ID = "client-alpha"


def assertion(client_key, audience, jti=None):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": audience,
            "iat": now,
            "exp": now + 60,
            "jti": jti or uuid.uuid4().hex,
        },
        client_key,
        algorithm="EdDSA",
    )


def token_call(client, client_key, settings, jti=None):
    return client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(client_key, settings.token_endpoint, jti=jti),
        },
    )


@pytest.fixture
def auth_server(tmp_path):
    settings = Settings(
        issuer_url="http://testserver",
        resource_audience="mcp://router",
        keys_dir=tmp_path,
        clients_file=tmp_path / "clients.json",
        allowed_hosts=["testserver"],
        token_rate_limit_per_minute=5,
    )
    client_key = keys.load_or_create_key(tmp_path / "client.pem")
    write_clients(
        settings.clients_file,
        {CLIENT_ID: {"public_key": keys.public_pem(client_key).decode(), "scopes": ["mcp:documents:read"]}},
    )
    return settings, client_key, TestClient(build_app(settings))


def test_token_endpoint_rate_limits(auth_server):
    settings, client_key, client = auth_server

    codes = [token_call(client, client_key, settings).status_code for _ in range(7)]

    assert codes[:5] == [200] * 5
    assert 429 in codes[5:]
    limited = token_call(client, client_key, settings)
    assert limited.json()["error"] == "too_many_requests"
    assert int(limited.headers["retry-after"]) >= 1


def test_replay_is_rejected_before_rate_limit_matters(auth_server):
    settings, client_key, client = auth_server
    jti = uuid.uuid4().hex

    first = token_call(client, client_key, settings, jti=jti)
    second = token_call(client, client_key, settings, jti=jti)

    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"] == "replay_detected"


def test_bucket_starts_full_and_empties():
    limiter = TokenBucketLimiter(per_minute=3)

    allowed = [limiter.allow("client")[0] for _ in range(3)]
    blocked = limiter.allow("client")

    assert allowed == [True, True, True]
    assert blocked[0] is False
    assert blocked[1] >= 1.0


async def test_in_process_replay_store_blocks_second_use():
    store = InProcessReplayStore()

    assert await store.check_and_store("jti-1", 60) is True
    assert await store.check_and_store("jti-1", 60) is False
    assert await store.check_and_store("jti-2", 60) is True


class FakeRedis:
    """Minimal SET NX EX surface, enough to verify the contract."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True


async def test_redis_replay_store_uses_set_nx():
    client = FakeRedis()
    store = RedisReplayStore(client, prefix="test:")

    assert await store.check_and_store("jti-1", 60) is True
    assert await store.check_and_store("jti-1", 60) is False
    assert client.values == {"test:jti-1": "1"}


def test_replay_store_factory_prefers_redis_when_configured():
    assert isinstance(build_replay_store(Settings(_env_file=None)), InProcessReplayStore)

    configured = Settings(_env_file=None, redis_url="redis://127.0.0.1:6379/0")
    assert isinstance(build_replay_store(configured), RedisReplayStore)
