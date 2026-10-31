"""End-to-end governance harness.

Runs every governance decision point against a real app instance and prints a
pass/fail table. Nothing is mocked except the key set and revocation lookup.

Run: python scripts/e2e_harness.py
"""

import json
import sys
import time
from pathlib import Path

import jwt
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_router import keys  # noqa: E402
from mcp_router.approvals import sign  # noqa: E402
from mcp_router.jwks_cache import StaticKeySet  # noqa: E402
from mcp_router.server import build_app  # noqa: E402
from mcp_router.settings import Settings  # noqa: E402

HOST = "127.0.0.1:8000"
KID = "harness-key"
SECRET = "harness-secret"

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2026-07-28", "capabilities": {}, "clientInfo": {"name": "harness", "version": "1"}},
}
ACCEPT = {"Accept": "application/json, text/event-stream"}


class NoRevocations:
    async def is_revoked(self, jti: str) -> bool:
        return False


def scoped_token(signing_key, settings, scopes: list[str]) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": settings.issuer_url,
            "sub": "harness-client",
            "aud": settings.resource_audience,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + 900,
            "jti": f"harness-{time.time_ns()}",
        },
        signing_key,
        algorithm="EdDSA",
        headers={"kid": KID},
    )


def call(client, bearer, name, arguments, request_id=10):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    return client.post("/mcp", json=payload, headers={**ACCEPT, "Authorization": f"Bearer {bearer}"})


def frame(response) -> dict:
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[len("data: ") :])
    return json.loads(response.text)


def main() -> int:
    workdir = Path("harness-data")
    workdir.mkdir(exist_ok=True)
    signing_key = keys.load_or_create_key(workdir / "harness_as.pem")

    settings = Settings(
        issuer_url="http://issuer.test",
        resource_audience="mcp://router",
        keys_dir=workdir,
        allowed_hosts=[HOST],
        audit_path=workdir / "audit.jsonl",
        approvals_db=workdir / "approvals.db",
        approval_hmac_secret=SECRET,
        roots=[workdir],
    )

    app = build_app(settings, key_set=StaticKeySet({KID: signing_key.public_key()}), revocations=NoRevocations())
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        results.append((name, ok, detail))

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        read_token = scoped_token(signing_key, settings, ["mcp:documents:read"])
        write_token = scoped_token(signing_key, settings, ["mcp:documents:write"])

        response = client.post("/mcp", json=INIT, headers={**ACCEPT, "Authorization": f"Bearer {read_token}"})
        check("initialize with a scoped token", response.status_code == 200, f"status={response.status_code}")

        response = client.post("/mcp", json=INIT, headers=ACCEPT)
        check("missing token is rejected", response.status_code == 401, f"status={response.status_code}")

        response = call(client, read_token, "documents.purge_document", {"request": {"tenant_id": "tenant-a", "document_id": "doc-001"}})
        check("cross-scope call is 403", response.status_code == 403, f"status={response.status_code}")

        response = client.post("/mcp", json=INIT, headers={**ACCEPT, "Host": "evil.example", "Authorization": f"Bearer {read_token}"})
        check("host mismatch is 400", response.status_code == 400, f"status={response.status_code}")

        response = client.get("/mcp", headers={"Authorization": f"Bearer {read_token}"})
        check("GET is 405 with Allow", response.status_code == 405 and response.headers.get("allow") == "POST", f"status={response.status_code}")

        response = call(client, read_token, "documents.read_document", {"request": {"tenant_id": "tenant-a", "document_id": "doc-001"}})
        check("authorized read succeeds", response.status_code == 200, f"status={response.status_code}")

        outside = workdir / ".." / "etc-passwd-escape"
        response = call(
            client,
            scoped_token(signing_key, settings, ["mcp:files:read"]),
            "files.read_text",
            {"request": {"path": str(outside)}},
        )
        body = json.dumps(frame(response))
        check("path outside roots is denied", "outside allowed roots" in body, body[:80])

        pending = frame(call(client, write_token, "documents.purge_document", {"request": {"tenant_id": "tenant-a", "document_id": "doc-001"}}))
        payload = json.loads(pending["result"]["content"][0]["text"])
        check("approval required for high-risk tool", payload["status"] == "approval_required", payload["status"])

        request_id = payload["request_id"]
        stamp = str(int(time.time()))
        body_bytes = b"{}"
        response = client.post(
            f"/approvals/{request_id}",
            content=body_bytes,
            headers={"x-approval-signature": sign(body_bytes, SECRET, int(stamp)), "x-approval-timestamp": stamp},
        )
        check("signed approval webhook accepted", response.status_code == 200, f"status={response.status_code}")

        response = client.post(
            f"/approvals/{request_id}",
            content=body_bytes,
            headers={"x-approval-signature": sign(body_bytes, SECRET, int(stamp)), "x-approval-timestamp": stamp},
        )
        check("replayed approval rejected", response.status_code == 409, f"status={response.status_code}")

        after = frame(call(client, write_token, "documents.purge_document", {"request": {"tenant_id": "tenant-a", "document_id": "doc-001"}}))
        after_body = json.loads(after["result"]["content"][0]["text"])
        check("approved purge executes once", after_body["status"] == "purged", after_body["status"])

        again = frame(call(client, write_token, "documents.purge_document", {"request": {"tenant_id": "tenant-a", "document_id": "doc-001"}}))
        again_body = json.loads(again["result"]["content"][0]["text"])
        check("approval is single-use", again_body["status"] == "approval_required", again_body["status"])

    width = max(len(name) for name, _, _ in results)
    failures = 0
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"{mark}  {name.ljust(width)}  {detail}")

    print(f"\n{len(results) - failures}/{len(results)} checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
