import time

import httpx


class RevocationCache:
    """Polls the issuer's revocation list and serves checks from cache.

    The resource server must never hit the issuer per request, so a revoked token
    stays usable for at most one TTL window. That window is the tradeoff.
    """

    def __init__(self, revoked_url: str, ttl_seconds: int = 30, timeout: float = 5.0) -> None:
        self._url = revoked_url
        self._ttl = ttl_seconds
        self._timeout = timeout
        self._revoked: set[str] = set()
        self._fetched_at = 0.0
        self.fetches = 0

    async def is_revoked(self, jti: str) -> bool:
        if self._is_stale():
            await self.refresh()
        return jti in self._revoked

    async def refresh(self) -> None:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(self._url)
            response.raise_for_status()
            payload = response.json()

        self._revoked = {entry["jti"] for entry in payload.get("revoked", []) if "jti" in entry}
        self._fetched_at = time.monotonic()
        self.fetches += 1

    def _is_stale(self) -> bool:
        return (time.monotonic() - self._fetched_at) > self._ttl
