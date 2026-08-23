"""Aggregate repeated rat-metrics runs without inventing statistical certainty."""
from __future__ import annotations

import collections
import os
import statistics
from typing import Any, Optional

from .telemetry import active, summarize

ABLATIONS = ("A0", "A1", "A2", "A3", "A4", "A5")


def _rat_root(root: str) -> str:
    root = os.path.abspath(root)
    return root if os.path.basename(root) == ".rat" else os.path.join(root, ".rat")


def _median(values):
    vals = [v for v in values if v is not None]
    return statistics.median(vals) if vals else None


def _run_ids(root: str) -> list[str]:
    runs = os.path.join(_rat_root(root), "telemetry", "runs")
    try:
        return sorted(name[:-6] for name in os.listdir(runs) if name.endswith(".jsonl"))
    except OSError:
        return []


def aggregate(root: str, *, challenge_id: Optional[str] = None,
              ablation_id: Optional[str] = None, include_ineligible: bool = False,
              min_runs: int = 3) -> dict[str, Any]:
    if ablation_id is not None and ablation_id not in ABLATIONS:
        raise ValueError("invalid ablation_id")
    if min_runs < 1:
        raise ValueError("min_runs must be >= 1")

    active_doc = active(root)
    active_id = str(active_doc["run_id"]) if active_doc else None
    docs = []
    ignored = []
    for run_id in _run_ids(root):
        if run_id == active_id:
            ignored.append({"run_id": run_id, "reason": "active run excluded from aggregate"})
            continue
        try:
            doc = summarize(root, run_id)
        except ValueError as exc:
            ignored.append({"run_id": run_id, "reason": str(exc)})
            continue
        if challenge_id is not None and doc.get("challenge_id") != challenge_id:
            continue
        if ablation_id is not None and doc.get("ablation_id") != ablation_id:
            continue
        docs.append(doc)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    for doc in docs:
        grouped[(str(doc.get("challenge_id", "challenge")), str(doc.get("ablation_id", "A0")))].append(doc)

    groups = []
    for (challenge, ablation), rows in grouped.items():
        rows.sort(key=lambda d: (int(d.get("attempt", 1)), str(d.get("benchmark_run_id", ""))))
        selected = rows if include_ineligible else [d for d in rows if d.get("eligible")]
        # Infrastructure failures and explicit skips are reported but excluded
        # from solver success-rate/performance denominators. Timeout/partial and
        # censored runs remain scored failures because they are solver outcomes.
        scored = [d for d in selected if d.get("status") not in {"infra-failure", "skipped"}]
        verified = [d for d in scored if d.get("metrics", {}).get("verified_solve")]

        def metric(path, source=scored):
            out = []
            for doc in source:
                cur: Any = doc.get("metrics", {})
                for key in path:
                    if not isinstance(cur, dict):
                        cur = None
                        break
                    cur = cur.get(key)
                out.append(cur)
            return out

        cache_reads = sum(int(d.get("metrics", {}).get("cache", {}).get("reads", 0) or 0) for d in scored)
        cache_hits = sum(int(d.get("metrics", {}).get("cache", {}).get("hits", 0) or 0) for d in scored)
        duplicate_total = sum(int(d.get("metrics", {}).get("tools", {}).get("duplicate_calls", 0) or 0) for d in scored)
        status_counts = collections.Counter(str(d.get("status", "?")) for d in selected)
        outcome_counts = collections.Counter(str(d.get("outcome", "?")) for d in selected)
        model_names = sorted({str(d.get("metrics", {}).get("model", {}).get("name"))
                              for d in scored if d.get("metrics", {}).get("model", {}).get("name")})

        group = {
            "challenge_id": challenge,
            "ablation_id": ablation,
            "runs_found": len(rows),
            "selected_runs": len(selected),
            "scored_runs": len(scored),
            "verified_runs": len(verified),
            "verified_solve_rate": (len(verified) / len(scored) if scored else None),
            "enough_repeats": len(scored) >= min_runs,
            "min_runs": min_runs,
            "excluded_ineligible": sum(1 for d in rows if not d.get("eligible")) if not include_ineligible else 0,
            "infra_failures": status_counts.get("infra-failure", 0),
            "skipped": status_counts.get("skipped", 0),
            "status_counts": dict(sorted(status_counts.items())),
            "outcome_counts": dict(sorted(outcome_counts.items())),
            "median": {
                # TTF/verification latency is conditioned on an actual verified
                # solve; solve rate is always reported beside it to avoid
                # rewarding variants that only solve an easy subset quickly.
                "time_to_flag_ms_verified": _median(metric(("time_to_flag_ms",), verified)),
                "time_to_verified_ms_verified": _median(metric(("time_to_verified_ms",), verified)),
                "wall_time_ms": _median(metric(("wall_time_ms",))),
                "peak_context_tokens": _median(metric(("peak_context_tokens",))),
                "input_tokens": _median(metric(("tokens", "input"))),
                "output_tokens": _median(metric(("tokens", "output"))),
                "cache_read_tokens": _median(metric(("tokens", "cache_read"))),
                "tool_calls": _median(metric(("tools", "calls"))),
                "duplicate_tool_calls": _median(metric(("tools", "duplicate_calls"))),
                "tool_wall_ms": _median(metric(("tools", "wall_ms"))),
                "model_wall_ms": _median(metric(("model", "wall_ms"))),
                "deep_escalations": _median(metric(("deep_escalations",))),
            },
            "duplicate_tool_calls_total": duplicate_total,
            "structured_cache": {
                "reads": cache_reads,
                "hits": cache_hits,
                "hit_ratio": (cache_hits / cache_reads if cache_reads else None),
            },
            "models": model_names,
            "attempts": [int(d.get("attempt", 1)) for d in rows],
            "run_ids": [str(d.get("benchmark_run_id")) for d in rows],
        }
        groups.append(group)

    order = {name: i for i, name in enumerate(ABLATIONS)}
    groups.sort(key=lambda g: (g["challenge_id"], order.get(g["ablation_id"], 99)))
    return {
        "report": "rat.benchmark-aggregate/v1",
        "filters": {
            "challenge_id": challenge_id,
            "ablation_id": ablation_id,
            "include_ineligible": include_ineligible,
            "min_runs": min_runs,
        },
        "groups": groups,
        "ignored_runs": ignored,
    }
