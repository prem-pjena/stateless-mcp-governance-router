import socket

import pytest

from mcp_router.containment import EgressPolicy, EgressViolation, PathPolicy, PathViolation
from mcp_router.server import AskRequest, sample_text


@pytest.fixture
def roots(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "note.txt").write_text("inside the root")
    (tmp_path / "outside.txt").write_text("outside the root")
    return tmp_path, allowed


def test_path_inside_root_is_resolved(roots):
    _, allowed = roots
    policy = PathPolicy([allowed])
    assert policy.resolve(str(allowed / "note.txt")).name == "note.txt"


def test_traversal_is_rejected(roots):
    _, allowed = roots
    policy = PathPolicy([allowed])
    with pytest.raises(PathViolation):
        policy.resolve(str(allowed / ".." / "outside.txt"))


def test_absolute_path_outside_root_is_rejected(roots):
    tmp_path, allowed = roots
    policy = PathPolicy([allowed])
    with pytest.raises(PathViolation):
        policy.resolve(str(tmp_path / "outside.txt"))


def test_symlink_escape_is_rejected(roots):
    tmp_path, allowed = roots
    link = allowed / "escape.txt"
    link.symlink_to(tmp_path / "outside.txt")

    policy = PathPolicy([allowed])
    with pytest.raises(PathViolation):
        policy.resolve(str(link))


def test_no_roots_means_everything_is_rejected(roots):
    _, allowed = roots
    policy = PathPolicy([])
    with pytest.raises(PathViolation):
        policy.resolve(str(allowed / "note.txt"))


def test_egress_denies_hosts_outside_the_allowlist():
    policy = EgressPolicy(["api.example.com"])
    with pytest.raises(EgressViolation):
        policy.check("evil.example.com")


def test_egress_denies_private_addresses(monkeypatch):
    policy = EgressPolicy(["internal.example.com"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(0, 0, 0, "", ("10.0.0.5", 0))])

    with pytest.raises(EgressViolation):
        policy.check("internal.example.com")


def test_egress_allows_public_addresses(monkeypatch):
    policy = EgressPolicy(["api.example.com"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(0, 0, 0, "", ("93.184.216.34", 0))])

    policy.check("api.example.com")


class FakeContext:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.prompts: list[str] = []

    async def sample(self, prompt):
        self.prompts.append(prompt)

        class Result:
            text = self.answer

        return Result()


@pytest.mark.asyncio
async def test_sampling_helper_returns_client_text():
    ctx = FakeContext("sampled answer")
    assert await sample_text(ctx, "what is up?") == "sampled answer"
    assert ctx.prompts == ["what is up?"]


def test_ask_request_model_is_strict():
    with pytest.raises(Exception):
        AskRequest(question=123)
