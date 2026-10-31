import json
import time
import uuid
from pathlib import Path


class AuditSink:
    """Append-only JSONL audit log.

    Writes are line-appended and never rewritten, so a record cannot be edited
    after the fact without leaving a trace. A failed write is reported, not
    swallowed: a governance system that silently loses audit records is worse
    than one that reports the failure.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.failures: list[str] = []

    def write(self, event: str, **fields) -> dict:
        record = {"timestamp": time.time(), "trace_id": uuid.uuid4().hex, "event": event}
        record.update({key: value for key, value in fields.items() if value is not None})

        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            self.failures.append(str(exc))
            raise

        return record

    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]


def build_sink(path: Path) -> AuditSink:
    return AuditSink(path)
