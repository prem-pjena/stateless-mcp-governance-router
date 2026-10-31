import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from pathlib import Path

MAX_SKEW_SECONDS = 300


class ApprovalError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def args_digest(tool: str, arguments: dict) -> str:
    payload = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def sign(body: bytes, secret: str, timestamp: int) -> str:
    message = f"{timestamp}.".encode() + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class ApprovalStore:
    """Pending approvals survive a restart; approval is single-use."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    tool TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    decided_at REAL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def create_pending(self, tool: str, arguments: dict) -> str:
        request_id = uuid.uuid4().hex
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO approvals (request_id, tool, digest, status, created_at) VALUES (?, ?, ?, ?, ?)",
                (request_id, tool, args_digest(tool, arguments), "pending", time.time()),
            )
        return request_id

    def approve(self, request_id: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status FROM approvals WHERE request_id = ?", (request_id,)
            ).fetchone()

            if row is None:
                raise ApprovalError("unknown_request")
            if row[0] != "pending":
                raise ApprovalError("already_decided")

            connection.execute(
                "UPDATE approvals SET status = 'approved', decided_at = ? WHERE request_id = ?",
                (time.time(), request_id),
            )

    def consume(self, tool: str, arguments: dict) -> bool:
        digest = args_digest(tool, arguments)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT request_id FROM approvals WHERE tool = ? AND digest = ? AND status = 'approved'",
                (tool, digest),
            ).fetchone()

            if row is None:
                return False

            connection.execute(
                "UPDATE approvals SET status = 'consumed' WHERE request_id = ?", (row[0],)
            )
            return True


def verify_webhook(body: bytes, signature: str, timestamp: str, secret: str, now: float | None = None) -> None:
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise ApprovalError("invalid_timestamp") from exc

    current = int(now if now is not None else time.time())
    if abs(current - sent_at) > MAX_SKEW_SECONDS:
        raise ApprovalError("stale_timestamp")

    expected = sign(body, secret, sent_at)
    if not hmac.compare_digest(expected, signature or ""):
        raise ApprovalError("invalid_signature")
