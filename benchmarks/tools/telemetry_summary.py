#!/usr/bin/env python3
"""Summarize architecture telemetry from immutable CTF-Rat benchmark results.

This tool intentionally consumes only ``challenge-results.jsonl`` records. It
never reads solver stdout, flags, exploit artifacts, or oracle internals. The
output is therefore suitable for public-safe benchmark reporting as long as the
input result records follow the same boundary.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


class TelemetryError(ValueError):
    pass


def _number(value: Any, name: str, *, integer: bool = False) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TelemetryError(f"{name} must be numeric or null")
    if value < 0:
        raise TelemetryError(f"{name} must be non-negative")
    if integer and int(value) != value:
        raise TelemetryError(f"{name} must be an integer")
    return int(value) if integer else value


def _metric(metrics: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in metrics and metrics[name] is not None:
            return metrics[name]
    return None


def _duplicate_breakdown(value: Any) -> Counter[str]:
    out: Counter[str] = Counter()
    if value is None:
        return out
    if isinstance(value, dict):
        for tool, count in value.items():
            if not isinstance(tool, str) or not tool:
                raise TelemetryError("duplicate_tool_calls keys must be non-empty strings")
            parsed = _number(count, f"duplicate_tool_calls[{tool}]", integer=True)
            if parsed:
                out[tool] += parsed
        return out
    if isinstance(value, list):
        for tool in value:
            if not isinstance(tool, str) or not tool:
                raise TelemetryError("duplicate_tool_calls entries must be non-empty strings")
            out[tool] += 1
        return out
    raise TelemetryError("duplicate_tool_calls must be an object, array, or null")


def _iter_result_paths(values: Iterable[str]) -> Iterable[Path]:
    for value in values:
        path = Path(value)
        if path.is_file():
            yield path
            continue
        if path.is_dir():
            found = sorted(path.rglob("challenge-results.jsonl"))
            if not found:
                raise TelemetryError(f"no challenge-results.jsonl under {path}")
            yield from found
            continue
        raise TelemetryError(f"result path does not exist: {path}")


def read_results(values: Iterable[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in _iter_result_paths(values):
        for line_no, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TelemetryError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict) or row.get("schema") != "rat.benchmark-result/v1":
                raise TelemetryError(f"{path}:{line_no}: expected rat.benchmark-result/v1")
            if not isinstance(row.get("metrics"), dict):
                raise TelemetryError(f"{path}:{line_no}: metrics must be an object")
            rows.append(row)
    if not rows:
        raise TelemetryError("no benchmark results found")
    return rows


def _median(values: list[int | float]) -> int | float | None:
    return statistics.median(values) if values else None


def summarize(rows: list[dict[str, Any]], *, attempt_one_only: bool = True) -> dict[str, Any]:
    selected = [r for r in rows if not attempt_one_only or r.get("attempt") == 1]
    if not selected:
        raise TelemetryError("no selected benchmark results")

    time_to_flag: list[int | float] = []
    first_primitive: list[int | float] = []
    peak_context: list[int | float] = []
    input_tokens = output_tokens = total_tokens = 0
    cache_creation_tokens = cache_read_tokens = 0
    tool_calls = duplicate_calls = cacheable_invocations = 0
    cache_hits = cache_lookups = 0
    duplicate_breakdown: Counter[str] = Counter()
    verified = 0
    solve_claimed = 0

    for row in selected:
        metrics = row["metrics"]
        if row.get("outcome") == "verified" and row.get("oracle", {}).get("passed") is True:
            verified += 1
        if row.get("outcome") in {"verified", "solve-claimed"}:
            solve_claimed += 1

        value = _number(_metric(metrics, "time_to_flag_seconds", "tts_seconds"), "time_to_flag_seconds")
        if value is not None:
            time_to_flag.append(value)
        value = _number(metrics.get("first_primitive_seconds"), "first_primitive_seconds")
        if value is not None:
            first_primitive.append(value)
        value = _number(metrics.get("peak_context_tokens"), "peak_context_tokens", integer=True)
        if value is not None:
            peak_context.append(value)

        legacy_total = _number(metrics.get("tokens"), "tokens", integer=True)
        current_input = _number(metrics.get("input_tokens"), "input_tokens", integer=True)
        current_output = _number(metrics.get("output_tokens"), "output_tokens", integer=True)
        current_total = _number(metrics.get("total_tokens"), "total_tokens", integer=True)
        input_tokens += current_input or 0
        output_tokens += current_output or 0
        if current_total is not None:
            total_tokens += current_total
        elif current_input is not None or current_output is not None:
            total_tokens += (current_input or 0) + (current_output or 0)
        else:
            total_tokens += legacy_total or 0

        cache_creation_tokens += _number(metrics.get("cache_creation_tokens"), "cache_creation_tokens", integer=True) or 0
        cache_read_tokens += _number(metrics.get("cache_read_tokens"), "cache_read_tokens", integer=True) or 0
        tool_calls += _number(metrics.get("tool_calls"), "tool_calls", integer=True) or 0
        cacheable_invocations += _number(metrics.get("cacheable_invocations"), "cacheable_invocations", integer=True) or 0
        cache_hits += _number(metrics.get("cache_hits"), "cache_hits", integer=True) or 0
        cache_lookups += _number(metrics.get("cache_lookups"), "cache_lookups", integer=True) or 0

        structured_duplicates = _duplicate_breakdown(metrics.get("duplicate_tool_calls"))
        duplicate_breakdown.update(structured_duplicates)
        structured_count = sum(structured_duplicates.values())
        legacy_duplicates = _number(metrics.get("duplicate_calls"), "duplicate_calls", integer=True)
        duplicate_calls += structured_count if metrics.get("duplicate_tool_calls") is not None else (legacy_duplicates or 0)

    denominator = len(selected)
    return {
        "schema": "rat.benchmark-telemetry-summary/v1",
        "result_count": denominator,
        "attempt_one_only": attempt_one_only,
        "metrics": {
            "verified_solve_rate": verified / denominator,
            "solve_claim_rate": solve_claimed / denominator,
            "median_time_to_flag_seconds": _median(time_to_flag),
            "median_first_primitive_seconds": _median(first_primitive),
            "median_peak_context_tokens": _median(peak_context),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "cache_creation_tokens": cache_creation_tokens,
            "cache_read_tokens": cache_read_tokens,
            "tool_calls": tool_calls,
            "tool_calls_per_result": tool_calls / denominator if tool_calls else None,
            "duplicate_tool_calls": duplicate_calls,
            "duplicate_tool_call_rate": (duplicate_calls / cacheable_invocations) if cacheable_invocations else None,
            "duplicate_tool_call_breakdown": dict(sorted(duplicate_breakdown.items())),
            "cache_hits": cache_hits,
            "cache_lookups": cache_lookups,
            "cache_hit_ratio": (cache_hits / cache_lookups) if cache_lookups else None,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="summarize CTF-Rat benchmark architecture telemetry")
    parser.add_argument("results", nargs="+", help="challenge-results.jsonl file or directory containing run results")
    parser.add_argument("--all-attempts", action="store_true", help="include retries; default is attempt=1 only")
    parser.add_argument("--output", help="write JSON summary to this path in addition to stdout")
    args = parser.parse_args(argv)
    try:
        summary = summarize(read_results(args.results), attempt_one_only=not args.all_attempts)
        encoded = json.dumps(summary, sort_keys=True, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(encoded)
        sys.stdout.write(encoded)
        return 0
    except TelemetryError as exc:
        print(f"[rat-bench:telemetry] {exc}", file=sys.stderr)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
