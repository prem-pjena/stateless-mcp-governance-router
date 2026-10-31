"""Verifies the replay store against a real Redis.

Skips (rather than fails) when no Redis is reachable, so the suite still runs on a
machine without one.
"""

import os

import pytest
import redis.asyncio as redis

from mcp_router.replay import RedisReplayStore, build_replay_store
from mcp_router.settings import Settings

TEST_DB_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/9")


@pytest.fixture
async def client():
    connection = redis.from_url(TEST_DB_URL)

    try:
        await connection.ping()
    except Exception as exc:  # noqa: BLE001 - a missing Redis is a skip, not a failure
        pytest.skip(f"no live redis: {exc}")

    await connection.flushdb()
    try:
        yield connection
    finally:
        await connection.flushdb()
        await connection.aclose()


async def test_replay_store_round_trip_against_redis(client):
    store = RedisReplayStore(client, prefix="test:")

    assert await store.check_and_store("jti-1", 60) is True
    assert await store.check_and_store("jti-1", 60) is False
    assert await client.exists("test:jti-1") == 1
    assert 0 < await client.ttl("test:jti-1") <= 60


async def test_two_instances_share_the_same_replay_state(client):
    """This is the actual multi-replica claim: a second server sees the first one's jti."""
    first = RedisReplayStore(client, prefix="shared:")
    second = RedisReplayStore(client, prefix="shared:")

    assert await first.check_and_store("jti-2", 60) is True
    assert await second.check_and_store("jti-2", 60) is False


async def test_factory_uses_redis_when_configured(client):
    store = build_replay_store(Settings(_env_file=None, redis_url=TEST_DB_URL))

    assert isinstance(store, RedisReplayStore)
    assert await store.check_and_store("jti-3", 60) is True
    assert await store.check_and_store("jti-3", 60) is False
