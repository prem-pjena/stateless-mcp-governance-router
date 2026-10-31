import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Client:
    client_id: str
    public_key_pem: bytes
    scopes: frozenset[str] = field(default_factory=frozenset)
    tenant_id: str | None = None


def load_clients(path: Path) -> dict[str, Client]:
    if not path.exists():
        return {}

    raw = json.loads(path.read_text())
    clients: dict[str, Client] = {}
    for client_id, entry in raw.items():
        clients[client_id] = Client(
            client_id=client_id,
            public_key_pem=entry["public_key"].encode(),
            scopes=frozenset(entry.get("scopes", [])),
            tenant_id=entry.get("tenant_id"),
        )
    return clients


def write_clients(path: Path, entries: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2))
