"""C5 bounded state-compact projection (M1-4, DESIGN_v2 S10.1).

Priority order (never-drop tiers first): invalidating findings > confirmed
facts > PASS primitives > active hypotheses > next probes > recent
ruled-out. Droppable tiers are trimmed oldest-first until the estimate fits
budget_tokens. Same view + budget_tokens + cursor always yields the same
output (pure function over already-materialized state, no I/O).
"""
from __future__ import annotations
import json

def estimate_tokens(obj):
    """Rough token estimate (~4 bytes/token) for a JSON-serializable value."""
    return max(1, len(json.dumps(obj, ensure_ascii=False, sort_keys=True)) // 4)

def _findings_by_priority(findings):
    invalidating = {k: v for k, v in findings.items() if v.get("state") == "invalidated"}
    confirmed = {k: v for k, v in findings.items()
                 if v.get("state") in ("confirmed", "verified") and k not in invalidating}
    return invalidating, confirmed

def _take_newest_first(name, pairs, rebuild, remaining, omitted_counts):
    kept = []
    budget = remaining
    for key, value in reversed(pairs):
        cost = estimate_tokens(value)
        if cost <= budget:
            kept.append((key, value)); budget -= cost
        else:
            break
    omitted_counts[name] = len(pairs) - len(kept)
    return rebuild(list(reversed(kept))), budget

def budget_compact(view, *, budget_tokens=None, cursor=None):
    invalidating_findings, confirmed_findings = _findings_by_priority(view.get("findings", {}) or {})
    pass_primitives = {k: v for k, v in (view.get("primitives", {}) or {}).items() if v.get("status") == "pass"}
    hypotheses = dict(view.get("hypotheses", {}) or {})
    next_probes = list(view.get("next_probes", []) or [])
    ruled_out = dict(view.get("ruled_out", {}) or {})

    fixed = {
        "invalidating_findings": invalidating_findings,
        "confirmed_findings": confirmed_findings,
        "pass_primitives": pass_primitives,
    }
    if budget_tokens is None:
        return {**fixed, "hypotheses": hypotheses, "next_probes": next_probes, "ruled_out": ruled_out,
                "truncated": False, "omitted_counts": {}, "cursor": cursor}

    remaining = max(0, budget_tokens - estimate_tokens(fixed))
    omitted_counts = {}
    hyp_out, remaining = _take_newest_first(
        "hypotheses", list(hypotheses.items()), dict, remaining, omitted_counts)
    next_out, remaining = _take_newest_first(
        "next_probes", list(enumerate(next_probes)), lambda ps: [v for _, v in ps], remaining, omitted_counts)
    ruled_out_out, remaining = _take_newest_first(
        "ruled_out", list(ruled_out.items()), dict, remaining, omitted_counts)

    truncated = any(v > 0 for v in omitted_counts.values())
    return {**fixed, "hypotheses": hyp_out, "next_probes": next_out, "ruled_out": ruled_out_out,
            "truncated": truncated, "omitted_counts": omitted_counts, "cursor": cursor}
