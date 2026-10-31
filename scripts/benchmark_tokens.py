"""Measures the cost of tool discovery under full exposure vs progressive disclosure.

Run: python scripts/benchmark_tokens.py
"""

import json
import statistics
import time

from mcp_router.registry import ToolRegistry
from mcp_router.server import build_registry

ITERATIONS = 100


def payload_for(registry: ToolRegistry, scopes: set[str], include_extended: bool) -> list[dict]:
    return [
        {
            "name": spec.name,
            "description": spec.description,
            "namespace": spec.namespace,
            "scope": spec.scope,
            "schema_version": spec.schema_version,
        }
        for spec in registry.visible_to(scopes, include_extended)
    ]


def measure(registry: ToolRegistry, scopes: set[str], include_extended: bool) -> tuple[int, float, float]:
    sizes: list[int] = []
    timings: list[float] = []

    for _ in range(ITERATIONS):
        start = time.perf_counter()
        encoded = json.dumps(payload_for(registry, scopes, include_extended))
        timings.append((time.perf_counter() - start) * 1000)
        sizes.append(len(encoded))

    return sizes[-1], statistics.median(timings), sorted(timings)[int(len(timings) * 0.95) - 1]


def main() -> None:
    registry = build_registry()
    broad_scopes = {"mcp:documents:read", "mcp:documents:write", "mcp:reports:read", "mcp:files:read"}

    full_size, full_p50, full_p95 = measure(registry, broad_scopes, include_extended=True)
    narrow, narrow_p50, narrow_p95 = measure(registry, {"mcp:documents:read"}, include_extended=False)

    print(f"iterations: {ITERATIONS}")
    print(f"full exposure       : {full_size:>6} bytes  p50={full_p50:.4f} ms  p95={full_p95:.4f} ms")
    print(f"progressive (scoped): {narrow:>6} bytes  p50={narrow_p50:.4f} ms  p95={narrow_p95:.4f} ms")

    if full_size:
        saved = 100 * (full_size - narrow) / full_size
        print(f"payload reduction   : {saved:.1f}%")


if __name__ == "__main__":
    main()
