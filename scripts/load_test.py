"""Load test against a running router.

Usage: python scripts/load_test.py [base-url] [requests] [concurrency]

Measures the governance path itself: an unauthenticated request must be rejected by
ingress/enforcement, so this exercises the guard chain rather than the tool logic.
"""

import asyncio
import statistics
import sys
import time

import httpx

DEFAULT_URL = "http://127.0.0.1:8010"
HOST_HEADER = "127.0.0.1:8010"


async def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    total = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    concurrency = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    url = f"{base}/mcp"

    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    statuses: list[int] = []
    errors = 0

    headers = {"Host": HOST_HEADER, "Accept": "application/json, text/event-stream"}
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.post(url, json=payload, headers=headers)

        async def worker() -> None:
            nonlocal errors
            async with semaphore:
                start = time.perf_counter()
                try:
                    response = await client.post(url, json=payload, headers=headers)
                except Exception:  # noqa: BLE001
                    errors += 1
                    return
                latencies.append((time.perf_counter() - start) * 1000)
                statuses.append(response.status_code)

        started = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(total)))
        elapsed = time.perf_counter() - started

    if not latencies:
        print("no successful requests")
        return 1

    ordered = sorted(latencies)
    print(f"target: {url} (unauthenticated — expected 401)")
    print(f"requests: {total}  concurrency: {concurrency}  wall: {elapsed:.2f}s")
    print(f"throughput: {total / elapsed:.1f} req/s")
    print(f"latency p50={statistics.median(ordered):.1f} ms  "
          f"p95={ordered[int(len(ordered) * 0.95) - 1]:.1f} ms  "
          f"p99={ordered[int(len(ordered) * 0.99) - 1]:.1f} ms")
    print(f"errors: {errors}  status codes: {sorted(set(statuses))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
