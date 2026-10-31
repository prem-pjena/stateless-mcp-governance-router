import time


class TokenBucketLimiter:
    """In-process limiter for the token endpoint.

    Deliberately simple: one bucket per client id. With more than one authorization
    server replica the effective limit multiplies, so a shared store (Redis) is the
    next step — that limitation is documented rather than hidden.
    """

    def __init__(self, per_minute: int) -> None:
        self.capacity = max(1, per_minute)
        self.refill_per_second = self.capacity / 60.0
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        tokens, last_seen = self._buckets.get(key, (float(self.capacity), now))

        tokens = min(float(self.capacity), tokens + (now - last_seen) * self.refill_per_second)

        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            retry_after = (1.0 - tokens) / self.refill_per_second
            return False, max(1.0, retry_after)

        self._buckets[key] = (tokens - 1.0, now)
        return True, 0.0
