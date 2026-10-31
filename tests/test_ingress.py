import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_router.ingress_guard import IngressGuardMiddleware

HOST = "127.0.0.1:8000"
ORIGIN = "http://127.0.0.1:8000"


@pytest.fixture
def client(tmp_path):
    from mcp_router.settings import Settings
    from mcp_router.server import build_app

    async def ok(request):
        return JSONResponse({"ok": True})

    settings = Settings(
        keys_dir=tmp_path,
        issuer_url="http://127.0.0.1:9",
        allowed_hosts=[HOST],
        allowed_origins=[ORIGIN],
    )

    stub = TestClient(
        Starlette(
            routes=[Route("/mcp", ok, methods=["POST", "GET"])],
            middleware=[
                Middleware(IngressGuardMiddleware, allowed_hosts=[HOST], allowed_origins=[ORIGIN])
            ],
        ),
        base_url="http://127.0.0.1:8000",
    )

    return stub, TestClient(build_app(settings), base_url="http://127.0.0.1:8000"), settings


def test_allowed_host_and_origin_pass(client):
    stub, _, _ = client
    response = stub.post("/mcp", json={}, headers={"Origin": ORIGIN})
    assert response.status_code == 200


def test_unknown_host_gets_header_mismatch(client):
    stub, _, _ = client
    response = stub.post("/mcp", json={}, headers={"Host": "evil.example"})
    assert response.status_code == 400
    assert response.json() == {"error": "HeaderMismatch", "detail": "host"}


def test_unknown_origin_gets_header_mismatch(client):
    stub, _, _ = client
    response = stub.post("/mcp", json={}, headers={"Origin": "http://evil.example"})
    assert response.status_code == 400
    assert response.json() == {"error": "HeaderMismatch", "detail": "origin"}


def test_browser_request_without_origin_is_rejected(client):
    stub, _, _ = client
    response = stub.post("/mcp", json={}, headers={"User-Agent": "Mozilla/5.0 (Macintosh)"})
    assert response.status_code == 400
    assert response.json()["detail"] == "missing_origin"


def test_unconfigured_allowlist_fails_closed():
    app = Starlette(
        routes=[Route("/mcp", lambda request: JSONResponse({}), methods=["POST"])],
        middleware=[Middleware(IngressGuardMiddleware, allowed_hosts=[], allowed_origins=[])],
    )
    response = TestClient(app, base_url="http://127.0.0.1:8000").post("/mcp", json={})
    assert response.status_code == 400


def test_get_is_405_with_allow_header(client):
    stub, _, _ = client
    response = stub.get("/mcp")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"


def test_real_mcp_app_rejects_wrong_host_before_auth(client):
    _, real, _ = client
    response = real.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Host": "evil.example", "Accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "HeaderMismatch"


def test_real_mcp_app_still_returns_405_on_get(client):
    _, real, _ = client
    assert real.get("/mcp").status_code == 405
