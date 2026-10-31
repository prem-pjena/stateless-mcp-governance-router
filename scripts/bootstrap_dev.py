"""Creates local development keys and a registered client.

Run once after cloning: python scripts/bootstrap_dev.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_router import keys  # noqa: E402
from mcp_router.clients import write_clients  # noqa: E402

CLIENT_ID = "client-alpha"
SCOPES = ["mcp:documents:read", "mcp:documents:write", "mcp:reports:read", "mcp:files:read", "mcp:tools:extended"]


def main() -> None:
    keys_dir = Path("keys")
    keys_dir.mkdir(parents=True, exist_ok=True)

    client_key = keys.load_or_create_key(keys_dir / f"{CLIENT_ID}.pem")
    write_clients(
        keys_dir / "clients.json",
        {
            CLIENT_ID: {
                "public_key": keys.public_pem(client_key).decode(),
                "scopes": SCOPES,
                "tenant_id": "tenant-a",
            }
        },
    )

    print(json.dumps({"client_id": CLIENT_ID, "scopes": SCOPES, "key": str(keys_dir / f"{CLIENT_ID}.pem")}, indent=2))


if __name__ == "__main__":
    main()
