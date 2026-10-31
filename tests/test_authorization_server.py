import time
import uuid

import jwt
import pytest
from starlette.testclient import TestClient

from mcp_router import keys
from mcp_router.authorization_server import build_app
from mcp_router.clients import write_clients
from mcp_router.settings import Settings

CLIENT_ID = "client-alpha"


@pytest.fixture
def env(tmp_path):
    settings = Settings(
        issuer_url="http://testserver",
        resource_audience="mcp://router",
        keys_dir=tmp_path,
        clients_file=tmp_path / "clients.json",
        allowed_hosts=["testserver"],
    )
    client_key = keys.load_or_create_key(tmp_path / "client_alpha.pem")
    write_clients(
        settings.clients_file,
        {
            CLIENT_ID: {
                "public_key": keys.public_pem(client_key).decode(),
                "scopes": ["mcp:documents:read", "mcp:reports:read"],
                "tenant_id": "tenant-a",
            }
        },
    )
    return settings, client_key, TestClient(build_app(settings))


def assertion(client_key, *, audience, ttl=60, jti=None, client_id=CLIENT_ID, key=None):
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + ttl,
        "jti": jti or uuid.uuid4().hex,
    }
    return jwt.encode(payload, key or client_key, algorithm="EdDSA")


def token_request(client, client_key, audience, **kwargs):
    return client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": kwargs.get("client_id", CLIENT_ID),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(client_key, audience=audience, **{
                k: v for k, v in kwargs.items() if k in {"ttl", "jti", "key"}
            }),
            "scope": kwargs.get("scope", "mcp:documents:read"),
        },
    )


def test_metadata_and_jwks(env):
    settings, _, client = env
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["token_endpoint"] == settings.token_endpoint
    assert metadata["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]
    assert metadata["grant_types_supported"] == ["client_credentials"]
    assert "register" not in metadata

    key_set = client.get("/.well-known/jwks.json").json()["keys"][0]
    assert key_set["alg"] == "EdDSA"
    assert key_set["crv"] == "Ed25519"
    assert key_set["kid"]


def test_token_is_audience_bound_and_scoped(env):
    settings, client_key, client = env
    response = token_request(client, client_key, settings.token_endpoint)
    assert response.status_code == 200, response.text

    body = response.json()
    claims = jwt.decode(
        body["access_token"],
        keys.public_key_for(settings.signing_key_path),
        algorithms=["EdDSA"],
        audience="mcp://router",
    )
    assert claims["scope"] == "mcp:documents:read"
    assert claims["tenant_id"] == "tenant-a"
    assert claims["exp"] - claims["iat"] == settings.access_token_ttl_seconds


def test_wrong_signature_rejected(env):
    settings, _, client = env
    other_key = keys.generate_key()
    response = token_request(client, other_key, settings.token_endpoint)
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client_assertion"


def test_expired_assertion_rejected(env):
    settings, client_key, client = env
    now = int(time.time())
    expired = jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": settings.token_endpoint,
            "iat": now - 600,
            "exp": now - 300,
            "jti": uuid.uuid4().hex,
        },
        client_key,
        algorithm="EdDSA",
    )
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": expired,
        },
    )
    assert response.status_code == 401
    assert response.json()["error"] == "assertion_expired"


def test_replayed_jti_rejected(env):
    settings, client_key, client = env
    jti = uuid.uuid4().hex
    first = token_request(client, client_key, settings.token_endpoint, jti=jti)
    second = token_request(client, client_key, settings.token_endpoint, jti=jti)
    assert first.status_code == 200
    assert second.status_code == 400
    assert second.json()["error"] == "replay_detected"


def test_wrong_audience_rejected(env):
    _, client_key, client = env
    response = token_request(client, client_key, "http://evil.example/token")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client_assertion"


def test_malformed_assertion_rejected(env):
    _, _, client = env
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": "not-a-jwt",
        },
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client_assertion"


def test_scope_beyond_grant_rejected(env):
    settings, client_key, client = env
    response = token_request(client, client_key, settings.token_endpoint, scope="mcp:documents:read mcp:ledger:write")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


def test_unsupported_grant_type(env):
    settings, client_key, client = env
    response = client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(client_key, audience=settings.token_endpoint),
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"


def test_revocation_is_published(env):
    settings, client_key, client = env
    token = token_request(client, client_key, settings.token_endpoint).json()
    claims = jwt.decode(token["access_token"], options={"verify_signature": False})

    response = client.post(
        "/revoke",
        data={
            "client_id": CLIENT_ID,
            "client_assertion": assertion(client_key, audience=settings.token_endpoint),
            "jti": claims["jti"],
        },
    )
    assert response.status_code == 200

    published = client.get("/revoked").json()["revoked"]
    assert claims["jti"] in {entry["jti"] for entry in published}
