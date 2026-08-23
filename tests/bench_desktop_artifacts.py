#!/usr/bin/env python3
"""Deterministic microbenchmark for CTF-Rat Desktop artifact discovery.

This is a measurement harness, not a performance gate. Fixtures are written
before timing. Full listing measures metadata/schema/object-size discovery;
unchanged listing measures the metadata-inventory generation fast path; preview
measures full SHA-256 verification with only a bounded retained prefix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.desktop_api import artifact_preview, list_artifacts
from ratlib.state_v2 import Stream

SCHEMA = "rat.desktop-artifact-benchmark/v1"


def _payload(index: int, size: int) -> bytes:
    seed = ("artifact-%08d-" % index).encode("ascii")
    return (seed * ((size // len(seed)) + 1))[:size]


def _write_artifacts(challenge_root: str, count: int, object_bytes: int) -> list[str]:
    store = Stream(challenge_root).root
    digests = []
    created = datetime.now(timezone.utc).isoformat()
    for index in range(count):
        data = _payload(index, object_bytes)
        hexdigest = hashlib.sha256(data).hexdigest()
        digest = "sha256:" + hexdigest
        digests.append(digest)
        obj = os.path.join(store, "objects", "sha256", hexdigest[:2], hexdigest[2:])
        meta = os.path.join(store, "metadata", "sha256", hexdigest[:2], hexdigest[2:] + ".json")
        os.makedirs(os.path.dirname(obj), mode=0o700, exist_ok=True)
        os.makedirs(os.path.dirname(meta), mode=0o700, exist_ok=True)
        with open(obj, "wb") as out:
            out.write(data)
        record = {
            "schema": "rat.artifact/v1",
            "digest": digest,
            "size": len(data),
            "kind": "desktop-benchmark",
            "media_type": "application/octet-stream",
            "logical_name": "artifact-%08d.bin" % index,
            "created_at": created,
            "provenance": {"producer": "bench_desktop_artifacts"},
        }
        with open(meta, "w", encoding="utf-8") as out:
            json.dump(record, out, sort_keys=True)
            out.write("\n")
    return digests


def _percentile(samples: list[float], q: float) -> float:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def _stats(samples: list[float], prefix: str) -> dict[str, float]:
    return {
        "%s_p50_ms" % prefix: round(_percentile(samples, 0.50), 3),
        "%s_p95_ms" % prefix: round(_percentile(samples, 0.95), 3),
        "%s_max_ms" % prefix: round(max(samples), 3),
    }


def _measure(fn, iterations: int) -> dict[str, float]:
    fn()
    wall_samples = []
    cpu_samples = []
    for _ in range(iterations):
        wall_started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        fn()
        cpu_samples.append((time.process_time_ns() - cpu_started) / 1_000_000.0)
        wall_samples.append((time.perf_counter_ns() - wall_started) / 1_000_000.0)
    return {**_stats(wall_samples, "wall"), **_stats(cpu_samples, "cpu")}


def run_case(count: int, object_bytes: int, preview_bytes: int, iterations: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="ctf-rat-desktop-artifact-bench-") as root:
        digests = _write_artifacts(root, count, object_bytes)
        first = list_artifacts(root, limit=min(2000, count))
        generation = first["generation"]
        listing = _measure(lambda: list_artifacts(root, limit=min(2000, count)), iterations)
        unchanged = _measure(
            lambda: list_artifacts(root, limit=min(2000, count), known_generation=generation),
            iterations,
        )
        preview = _measure(
            lambda: artifact_preview(root, digests[-1], max_bytes=min(preview_bytes, 256 * 1024)),
            iterations,
        )
        wall_ratio = listing["wall_p50_ms"] / unchanged["wall_p50_ms"] if unchanged["wall_p50_ms"] else None
        cpu_ratio = listing["cpu_p50_ms"] / unchanged["cpu_p50_ms"] if unchanged["cpu_p50_ms"] else None
        return {
            "schema": SCHEMA,
            "artifact_count": count,
            "object_bytes_each": object_bytes,
            "total_object_bytes": count * object_bytes,
            "preview_bytes_requested": min(preview_bytes, 256 * 1024),
            "iterations": iterations,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "operations": {
                "list_artifacts_full": listing,
                "list_artifacts_unchanged_hint": unchanged,
                "preview_one": preview,
            },
            "unchanged_hint_wall_speedup_p50": None if wall_ratio is None else round(wall_ratio, 2),
            "unchanged_hint_cpu_speedup_p50": None if cpu_ratio is None else round(cpu_ratio, 2),
            "note": "full listing validates metadata/object-size; unchanged hint scans immutable metadata inventory only; preview performs full SHA-256 verification while retaining a bounded prefix",
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Measure CTF-Rat Desktop artifact projection cost")
    parser.add_argument("--artifacts", default="10,100,500", help="comma-separated artifact counts")
    parser.add_argument("--object-bytes", type=int, default=65536)
    parser.add_argument("--preview-bytes", type=int, default=131072)
    parser.add_argument("--iterations", type=int, default=7)
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    if args.object_bytes < 1:
        parser.error("--object-bytes must be >= 1")
    if args.preview_bytes < 1 or args.preview_bytes > 256 * 1024:
        parser.error("--preview-bytes must be between 1 and 262144")
    try:
        counts = [int(item) for item in args.artifacts.split(",") if item.strip()]
    except ValueError as exc:
        parser.error("--artifacts must contain integers")
    if not counts or any(count < 1 or count > 2000 for count in counts):
        parser.error("--artifacts must contain integers between 1 and 2000")
    for count in counts:
        print(json.dumps(run_case(count, args.object_bytes, args.preview_bytes, args.iterations), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
