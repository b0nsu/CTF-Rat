"""Evidence-preserving soft-budget state-compact projection.

Priority order (never-drop tiers first): invalidating findings > confirmed
facts > PASS primitives > active hypotheses > next probes > recent
ruled-out. Critical tiers are never dropped and may exceed ``budget_tokens``;
the budget limits only droppable tiers after critical evidence is accounted
for. Same view + budget_tokens + cursor always yields the same output (pure
function over already-materialized state, no I/O).
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

def truncate_by_item(items, budget_bytes, *, size_fn=None):
    """Item-boundary truncation for `rat query *` list-valued facts.

    Keeps items in original order, stopping at the first item boundary that
    would exceed budget_bytes -- never splits an item across the boundary.
    Independent of `_take_newest_first` (state-compact's newest-first/tiered
    semantics are a different concern and must not be touched by this)."""
    size_fn = size_fn or (lambda v: len(json.dumps(v, ensure_ascii=False, sort_keys=True).encode()))
    kept, used = [], 0
    for item in items:
        cost = size_fn(item)
        if used + cost > budget_bytes:
            break
        kept.append(item); used += cost
    return kept, len(kept) < len(items), len(items) - len(kept)

def truncate_lists_sharing_budget(named_lists, budget_bytes, *, size_fn=None):
    """Same contract as ``truncate_by_item``, but budget_bytes is a
    single per-query pool shared across several ordered fact-lists instead of
    being applied independently to each -- an envelope with N lists must not
    be able to grow to N*budget_bytes. Earlier lists in ``named_lists`` get
    priority: they see the full remaining pool before later ones."""
    size_fn = size_fn or (lambda v: len(json.dumps(v, ensure_ascii=False, sort_keys=True).encode()))
    remaining = budget_bytes
    kept, omitted, any_truncated = {}, {}, False
    for name, items in named_lists:
        k, trunc, omit = truncate_by_item(items, remaining, size_fn=size_fn)
        kept[name] = k
        omitted[name] = omit
        any_truncated = any_truncated or trunc
        remaining -= sum(size_fn(i) for i in k)
    return kept, any_truncated, omitted

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

    critical_tokens = estimate_tokens(fixed)
    remaining = max(0, budget_tokens - critical_tokens)
    omitted_counts = {}
    hyp_out, remaining = _take_newest_first(
        "hypotheses", list(hypotheses.items()), dict, remaining, omitted_counts)
    next_out, remaining = _take_newest_first(
        "next_probes", list(enumerate(next_probes)), lambda ps: [v for _, v in ps], remaining, omitted_counts)
    ruled_out_out, remaining = _take_newest_first(
        "ruled_out", list(ruled_out.items()), dict, remaining, omitted_counts)

    truncated = any(v > 0 for v in omitted_counts.values())
    projected = {**fixed, "hypotheses": hyp_out, "next_probes": next_out, "ruled_out": ruled_out_out,
                 "truncated": truncated, "omitted_counts": omitted_counts, "cursor": cursor}
    return {**projected, "budget_tokens": budget_tokens, "estimated_tokens": estimate_tokens(projected),
            "budget_exceeded_by_critical_tiers": critical_tokens > budget_tokens}
