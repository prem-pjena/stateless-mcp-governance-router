import json
import time

import jwt
import pytest
from starlette.testclient import TestClient

from mcp_router import keys
from mcp_router.approvals import sign
from mcp_router.audit import AuditSink
from mcp_router.jwks_cache import StaticKeySet
from mcp_router.settings import Settings

HOST = "127.0.0.1:8000"
KID = "k1"
SECRET = "test-approval-secret"


class NoRevocations:
    async def is_revoked(self, jti: str) -> bool:
        return False


@pytest.fixture
def gov(tmp_path):
    signing_key = keys.load_or_create_key(tmp_path / "as.pem")
    settings = Settings(
        issuer_url="http://issuer.test",
        resource_audience="mcp://router",
        keys_dir=tmp_path,
        allowed_hosts=[HOST],
        audit_path=tmp_path / "audit.jsonl",
        approvals_db=tmp_path / "approvals.db",
        approval_hmac_secret=SECRET,
    )

    from mcp_router.server import build_app

    app = build_app(
        settings,
        key_set=StaticKeySet({KID: signing_key.public_key()}),
        revocations=NoRevocations(),
    )

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        yield client, signing_key, settings, AuditSink(settings.audit_path)


def token(signing_key, settings, scopes):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": settings.issuer_url,
            "sub": "client-alpha",
            "aud": settings.resource_audience,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + 900,
            "jti": "jti-" + str(now) + str(scopes),
        },
        signing_key,
        algorithm="EdDSA",
        headers={"kid": KID},
    )


def call_purge(client, bearer, tenant="tenant-a", document="doc-001"):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "documents.purge_document",
            "arguments": {"request": {"tenant_id": tenant, "document_id": document}},
        },
    }
    return client.post(
        "/mcp",
        json=payload,
        headers={"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {bearer}"},
    )


def result_of(response) -> dict:
    for line in response.text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: ") :])
            text = payload["result"]["content"][0]["text"]
            return json.loads(text)
    raise AssertionError(f"no data frame in {response.text!r}")


def approve(client, request_id, body=b"{}", secret=SECRET, timestamp=None, signature=None):
    stamp = str(timestamp if timestamp is not None else int(time.time()))
    return client.post(
        f"/approvals/{request_id}",
        content=body,
        headers={
            "x-approval-signature": signature if signature is not None else sign(body, secret, int(stamp)),
            "x-approval-timestamp": stamp,
            "content-type": "application/json",
        },
    )


def test_purge_requires_approval_first(gov):
    client, signing_key, settings, _ = gov
    response = call_purge(client, token(signing_key, settings, ["mcp:documents:write"]))

    assert response.status_code == 200
    body = result_of(response)
    assert body["status"] == "approval_required"
    assert body["request_id"]


def test_webhook_rejects_bad_signature(gov):
    client, signing_key, settings, _ = gov
    request_id = result_of(call_purge(client, token(signing_key, settings, ["mcp:documents:write"])))["request_id"]

    response = approve(client, request_id, signature="deadbeef")
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_signature"


def test_webhook_rejects_stale_timestamp(gov):
    client, signing_key, settings, _ = gov
    request_id = result_of(call_purge(client, token(signing_key, settings, ["mcp:documents:write"])))["request_id"]

    response = approve(client, request_id, timestamp=int(time.time()) - 3600)
    assert response.status_code == 401
    assert response.json()["error"] == "stale_timestamp"


def test_webhook_rejects_replay(gov):
    client, signing_key, settings, _ = gov
    request_id = result_of(call_purge(client, token(signing_key, settings, ["mcp:documents:write"])))["request_id"]

    assert approve(client, request_id).status_code == 200
    replay = approve(client, request_id)
    assert replay.status_code == 409
    assert replay.json()["error"] == "already_decided"


def test_unknown_request_id_is_rejected(gov):
    client, _, _, _ = gov
    response = approve(client, "does-not-exist")
    assert response.status_code == 409
    assert response.json()["error"] == "unknown_request"


def test_approved_purge_executes_once(gov):
    client, signing_key, settings, _ = gov
    bearer = token(signing_key, settings, ["mcp:documents:write"])

    request_id = result_of(call_purge(client, bearer, document="doc-001"))["request_id"]
    approve(client, request_id)

    first = result_of(call_purge(client, bearer, document="doc-001"))
    assert first["status"] == "purged"

    second = result_of(call_purge(client, bearer, document="doc-001"))
    assert second["status"] == "approval_required"


def test_audit_sink_records_the_governance_trail(gov):
    client, signing_key, settings, sink = gov
    bearer = token(signing_key, settings, ["mcp:documents:write"])

    request_id = result_of(call_purge(client, bearer))["request_id"]
    approve(client, request_id)

    events = [event["event"] for event in sink.events()]
    assert "token_validation" in events
    assert "approval_requested" in events
    assert "approval_granted" in events

    record = sink.events()[0]
    assert {"timestamp", "trace_id", "event"} <= set(record)


def test_audit_failures_are_reported(tmp_path):
    sink = AuditSink(tmp_path / "audit.jsonl")
    blocker = tmp_path / "audit.jsonl"
    blocker.write_text("x")
    blocker.chmod(0o400)
    sink.path = tmp_path / "nested" / "audit.jsonl"
    sink.path.parent.mkdir()
    sink.path.parent.chmod(0o500)

    with pytest.raises(OSError):
        sink.write("token_validation", decision="allow")

    assert sink.failures
