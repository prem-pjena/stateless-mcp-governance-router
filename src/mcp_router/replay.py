import time
from typing import Protocol


class ReplayStore(Protocol):
    async def check_and_store(self, jti: str, ttl_seconds: int) -> bool: ...


class InProcessReplayStore:
    """Single-process store. Resets on restart and is not shared between workers."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    async def check_and_store(self, jti: str, ttl_seconds: int) -> bool:
        now = int(time.time())
        self._prune(now)

        if jti in self._seen:
            return False

        self._seen[jti] = now + ttl_seconds
        return True

    def _prune(self, now: int) -> None:
        for jti in [key for key, expiry in self._seen.items() if expiry <= now]:
            del self._seen[jti]


class RedisReplayStore:
    """Shared store, so the limit still holds with several authorization servers.

    Uses SET NX EX: the first caller wins, everyone else is a replay.
    """

    def __init__(self, client, prefix: str = "mcp:replay:") -> None:
        self._client = client
        self._prefix = prefix

    async def check_and_store(self, jti: str, ttl_seconds: int) -> bool:
        stored = await self._client.set(self._prefix + jti, "1", nx=True, ex=ttl_seconds)
        return bool(stored)


def build_replay_store(settings) -> ReplayStore:
    if settings.redis_url:
        import redis.asyncio as redis

        return RedisReplayStore(redis.from_url(settings.redis_url))
    return InProcessReplayStore()
