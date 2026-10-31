from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    issuer_url: str = "http://127.0.0.1:9000"
    resource_audience: str = "mcp://stateless-mcp-governance-router"
    keys_dir: Path = Path("keys")
    clients_file: Path = Path("keys/clients.json")

    as_host: str = "127.0.0.1"
    as_port: int = 9000
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000

    access_token_ttl_seconds: int = 900
    assertion_max_ttl_seconds: int = 300
    clock_skew_seconds: int = 5
    jwks_cache_seconds: int = 300

    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1:8000", "localhost:8000"])
    allowed_origins: list[str] = Field(default_factory=list)

    roots: list[Path] = Field(default_factory=list)
    egress_allowlist: list[str] = Field(default_factory=list)

    audit_path: Path = Path("logs/audit.jsonl")
    approvals_db: Path = Path("data/approvals.db")
    approval_hmac_secret: str = "dev-approval-secret"
    token_rate_limit_per_minute: int = 60
    redis_url: str | None = None

    @property
    def signing_key_path(self) -> Path:
        return self.keys_dir / "as_signing_key.pem"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer_url}/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer_url}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()
