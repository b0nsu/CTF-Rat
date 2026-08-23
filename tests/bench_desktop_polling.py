#!/usr/bin/env python3
"""Deterministic microbenchmark for CTF-Rat Desktop STATE polling.

This is a measurement harness, not a performance gate. It writes a synthetic,
valid STATE v2 JSONL stream directly so fixture construction does not measure
Stream.append() and then times the read-only projections used by ratd.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.desktop_api import event_delta, list_artifacts, snapshot, telemetry
from ratlib.state_v2 import EVENT_SCHEMA, stream_path

SCHEMA = "rat.desktop-poll-benchmark/v1"


def _write_stream(root: str, count: int) -> int:
    path = stream_path(root)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    stream_id = "stream_desktop_benchmark"
    with open(path, "w", encoding="utf-8") as out:
        for seq in range(1, count + 1):
            event = {
                "schema": EVENT_SCHEMA,
                "stream_id": stream_id,
                "seq": seq,
                "event_id": "evt_bench_%08d" % seq,
                "at": "2026-01-01T00:00:00+00:00",
                "actor": "benchmark",
                "task_id": "desktop-poll",
                "type": "hypothesis.recorded",
                "payload": {"hypothesis_id": "hyp_%08d" % seq},
                "caused_by": [],
            }
            out.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    return os.path.getsize(path)


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
    # Warm filesystem/page cache once; repeated samples then model steady-state
    # desktop polling rather than first-open disk latency. Wall-clock latency
    # and process CPU time are distinct signals and must not be conflated.
    fn()
    wall_samples = []
    cpu_samples = []
    for _ in range(iterations):
        wall_started = time.perf_counter_ns()
        cpu_started = time.process_time_ns()
        fn()
        cpu_samples.append((time.process_time_ns() - cpu_started) / 1_000_000.0)
        wall_samples.append((time.perf_counter_ns() - wall_started) / 1_000_000.0)
    return {
        **_stats(wall_samples, "wall"),
        **_stats(cpu_samples, "cpu"),
    }


def run_case(count: int, iterations: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="ctf-rat-desktop-bench-") as root:
        stream_bytes = _write_stream(root, count)
        midpoint = count // 2

        # Prime the opaque generation hint using the same validated fallback
        # path a real first poll uses. Subsequent unchanged polls echo it.
        primed = event_delta(root, after_seq=count, limit=500)
        cursor = primed["cursor"]
        hinted_idle = lambda: event_delta(
            root,
            after_seq=count,
            limit=500,
            stream_id=cursor["stream_id"],
            known_size=cursor.get("source_size"),
            known_mtime_ns=cursor.get("source_mtime_ns"),
        )

        operations = {
            "event_delta_idle_full_scan": _measure(lambda: event_delta(root, after_seq=count, limit=500), iterations),
            "event_delta_idle_unchanged_hint": _measure(hinted_idle, iterations),
            "event_delta_10_new": _measure(lambda: event_delta(root, after_seq=max(0, count - 10), limit=500), iterations),
            "snapshot_live": _measure(lambda: snapshot(root), iterations),
            "snapshot_midpoint": _measure(lambda: snapshot(root, until_seq=midpoint), iterations),
            "telemetry": _measure(lambda: telemetry(root), iterations),
            "artifact_listing_empty": _measure(lambda: list_artifacts(root, limit=500), iterations),
        }
        changed_names = ("event_delta_10_new", "snapshot_live", "telemetry", "artifact_listing_empty")
        idle_full = operations["event_delta_idle_full_scan"]
        idle_fast = operations["event_delta_idle_unchanged_hint"]
        wall_speedup = idle_full["wall_p50_ms"] / idle_fast["wall_p50_ms"] if idle_fast["wall_p50_ms"] else None
        cpu_speedup = idle_full["cpu_p50_ms"] / idle_fast["cpu_p50_ms"] if idle_fast["cpu_p50_ms"] else None
        return {
            "schema": SCHEMA,
            "event_count": count,
            "stream_bytes": stream_bytes,
            "iterations": iterations,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
            },
            "operations": operations,
            "unchanged_hint_wall_speedup_p50": None if wall_speedup is None else round(wall_speedup, 2),
            "unchanged_hint_cpu_speedup_p50": None if cpu_speedup is None else round(cpu_speedup, 2),
            "estimated_idle_poll_wall_ms_p50": idle_fast["wall_p50_ms"],
            "estimated_idle_poll_cpu_ms_p50": idle_fast["cpu_p50_ms"],
            "estimated_changed_poll_wall_ms_p50": round(sum(operations[name]["wall_p50_ms"] for name in changed_names), 3),
            "estimated_changed_poll_cpu_ms_p50": round(sum(operations[name]["cpu_p50_ms"] for name in changed_names), 3),
            "note": "changed poll totals are sequential cost estimates; the UI issues refresh requests concurrently",
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Measure CTF-Rat Desktop polling projection cost")
    parser.add_argument("--events", default="100,1000,5000", help="comma-separated STATE event counts")
    parser.add_argument("--iterations", type=int, default=7)
    args = parser.parse_args(argv)
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    try:
        counts = [int(item) for item in args.events.split(",") if item.strip()]
    except ValueError as exc:
        parser.error("--events must contain integers")
    if not counts or any(count < 1 for count in counts):
        parser.error("--events must contain positive integers")
    for count in counts:
        print(json.dumps(run_case(count, args.iterations), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
