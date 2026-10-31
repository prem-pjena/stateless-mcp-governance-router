import json
import time
import uuid

import jwt
import pytest
from pydantic import BaseModel
from starlette.testclient import TestClient

from mcp_router import keys
from mcp_router.jwks_cache import StaticKeySet
from mcp_router.registry import EXTENDED, RegistryError, ToolRegistry, ToolSpec
from mcp_router.server import build_app

ISSUER = "http://issuer.test"
AUDIENCE = "mcp://router"
HOST = "127.0.0.1:8000"
KID = "k1"


class In(BaseModel):
    tenant_id: str


class Out(BaseModel):
    tenant_id: str


def handler(request: In) -> Out:
    return Out(tenant_id=request.tenant_id)


def spec(**overrides) -> ToolSpec:
    values = {
        "name": "documents.read_document",
        "namespace": "documents",
        "scope": "mcp:documents:read",
        "description": "desc",
        "input_model": In,
        "result_model": Out,
        "handler": handler,
    }
    values.update(overrides)
    return ToolSpec(**values)


def test_registry_rejects_duplicate_names():
    registry = ToolRegistry()
    registry.register(spec())
    with pytest.raises(RegistryError):
        registry.register(spec())


def test_registry_rejects_namespace_mismatch():
    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(name="other.read_document"))


def test_registry_rejects_scope_namespace_mismatch():
    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(scope="mcp:reports:read"))


def test_registry_rejects_untyped_input_model():
    class Loose(BaseModel):
        payload: dict

    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(input_model=Loose))


def test_registry_rejects_any_annotation():
    from typing import Any

    class Loose(BaseModel):
        payload: Any

    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(input_model=Loose))


def test_registry_rejects_non_pydantic_models():
    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(result_model=dict))


def test_registry_rejects_unknown_tier():
    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(tier="experimental"))


def test_registry_rejects_missing_schema_version():
    with pytest.raises(RegistryError):
        ToolRegistry().register(spec(schema_version=""))


def test_visibility_follows_scope_and_tier():
    registry = ToolRegistry()
    registry.register(spec())
    registry.register(
        spec(
            name="reports.summarize_documents",
            namespace="reports",
            scope="mcp:reports:read",
            tier=EXTENDED,
        )
    )

    assert [s.name for s in registry.visible_to({"mcp:documents:read"}, include_extended=False)] == [
        "documents.read_document"
    ]
    assert len(registry.visible_to({"mcp:documents:read"}, include_extended=True)) == 1
    assert len(
        registry.visible_to({"mcp:documents:read", "mcp:reports:read"}, include_extended=True)
    ) == 2


@pytest.fixture
def governed(tmp_path):
    signing_key = keys.load_or_create_key(tmp_path / "as.pem")

    class NoRevocations:
        async def is_revoked(self, jti: str) -> bool:
            return False

    from mcp_router.settings import Settings

    settings = Settings(
        issuer_url=ISSUER,
        resource_audience=AUDIENCE,
        keys_dir=tmp_path,
        allowed_hosts=[HOST],
    )
    app = build_app(
        settings,
        key_set=StaticKeySet({KID: signing_key.public_key()}),
        revocations=NoRevocations(),
    )
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        yield client, signing_key, settings


def token(signing_key, settings, scopes, ttl=900):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": settings.issuer_url,
            "sub": "client-alpha",
            "aud": settings.resource_audience,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
        },
        signing_key,
        algorithm="EdDSA",
        headers={"kid": KID},
    )


def rpc(client, payload, bearer, host=HOST):
    return client.post(
        "/mcp",
        json=payload,
        headers={"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {bearer}"},
    )


def sse_json(response) -> dict:
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    return json.loads(response.text)


def test_initialize_succeeds_with_governed_token(governed):
    client, signing_key, settings = governed
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2026-07-28", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    }
    response = rpc(client, payload, token(signing_key, settings, ["mcp:documents:read"]))
    assert response.status_code == 200


def test_tool_listing_hides_tools_outside_the_token_scope(governed):
    client, signing_key, settings = governed
    payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    core_only = rpc(client, payload, token(signing_key, settings, ["mcp:documents:read"]))
    names = [tool["name"] for tool in sse_json(core_only)["result"]["tools"]]
    assert names == ["documents.read_document"]

    extended = rpc(
        client,
        payload,
        token(
            signing_key,
            settings,
            ["mcp:documents:read", "mcp:reports:read", "mcp:files:read", "mcp:tools:extended"],
        ),
    )
    names = [tool["name"] for tool in sse_json(extended)["result"]["tools"]]
    assert set(names) == {
        "documents.read_document",
        "reports.summarize_documents",
        "reports.ask_model",
        "files.read_text",
    }


def test_cross_namespace_call_is_rejected_with_403(governed):
    client, signing_key, settings = governed
    payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "reports.summarize_documents", "arguments": {"request": {"tenant_id": "tenant-a"}}},
    }
    response = rpc(client, payload, token(signing_key, settings, ["mcp:documents:read"]))
    assert response.status_code == 403
    assert response.json() == {
        "error": "insufficient_scope",
        "tool": "reports.summarize_documents",
        "required": "mcp:reports:read",
    }


def test_authorized_call_executes(governed):
    client, signing_key, settings = governed
    payload = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "reports.summarize_documents", "arguments": {"request": {"tenant_id": "tenant-a"}}},
    }
    response = rpc(client, payload, token(signing_key, settings, ["mcp:reports:read"]))
    assert response.status_code == 200
    body = json.dumps(sse_json(response))
    assert "document_count" in body


def test_core_tool_still_works(governed):
    client, signing_key, settings = governed
    payload = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "documents.read_document",
            "arguments": {"request": {"tenant_id": "tenant-a", "document_id": "doc-001"}},
        },
    }
    response = rpc(client, payload, token(signing_key, settings, ["mcp:documents:read"]))
    assert response.status_code == 200
    assert "Example document for Tenant A." in response.text
