"""Bounded, deterministic projection of the existing revq function/call map.

This does not recover new control flow, prove reachability, or interpret data flow.
The full revq map remains in revq's existing on-disk cache; only this projection
is returned to the model. No graph database or additional analysis pass.
"""
from __future__ import annotations

import json


def _size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def project_graph(rev, *, interesting=(), budget_bytes=16384, max_nodes=64):
    """Return graph facts, coverage and diagnostics from a cached revq map.

    Nodes are indivisible. Addresses are canonical node IDs; a call name resolves
    to an internal edge only when it identifies exactly one recovered function.
    An omitted target is never presented as an edge to a visible node.
    """
    if budget_bytes < 1 or max_nodes < 1:
        raise ValueError("budget_bytes and max_nodes must be positive")

    functions = {}
    non_addressed = 0
    for func in rev.get("functions", ()):
        address = func.get("addr")
        if isinstance(address, int) and not isinstance(address, bool) and address > 0:
            functions.setdefault(address, func)
        else:
            non_addressed += 1

    by_name = {}
    for addr, func in functions.items():
        by_name.setdefault(func.get("name", ""), []).append(addr)

    scores = {}
    for candidate in interesting:
        name = candidate.get("func")
        if isinstance(name, str):
            scores[name] = max(scores.get(name, 0), candidate.get("score", 0))

    def sort_key(item):
        addr, func = item
        name = func.get("name", "")
        return (name not in ("main", "_start"), -scores.get(name, 0),
                -(len(func.get("calls", ())) + func.get("ncallers", 0)), addr)

    ordered = sorted(functions.items(), key=sort_key)
    # Reserve space for envelope/coverage fields; the node payload is an
    # approximate budget rather than a hard bound on the complete JSON document.
    remaining = max(0, budget_bytes - 1024)
    selected = []
    for addr, func in ordered:
        if len(selected) >= max_nodes:
            break
        calls = sorted(set(str(c) for c in func.get("calls", ()) if c))
        internal = []
        named = []
        ambiguous = 0
        for name in calls:
            destinations = by_name.get(name, ())
            if len(destinations) == 1:
                internal.append(destinations[0])
            elif destinations:
                ambiguous += 1
            else:
                named.append(name)
        node = {
            "address": "0x%x" % addr,
            "name": func.get("name", "?"),
            "size": func.get("size", 0),
            "blocks": func.get("nblocks", 0),
            "internal_targets": sorted(set(internal)),
            "named_targets": named,
            "ambiguous_calls": ambiguous,
        }
        # Charge the complete target list so an exceptionally large node cannot
        # silently bypass the output budget. Convert to hex after selection.
        if _size(node) > remaining:
            continue
        selected.append(node)
        remaining -= _size(node)

    shown = {int(node["address"], 16) for node in selected}
    result_nodes = []
    edges = 0
    hidden_edges = 0
    ambiguous_calls = 0
    for node in selected:
        targets = node.pop("internal_targets")
        node["calls"] = ["0x%x" % addr for addr in targets if addr in shown]
        node["hidden_calls"] = sum(1 for addr in targets if addr not in shown)
        edges += len(node["calls"])
        hidden_edges += node["hidden_calls"]
        ambiguous_calls += node["ambiguous_calls"]
        result_nodes.append(node)

    total = len(functions)
    missing = total - len(selected)
    engine_complete = rev.get("engine") == "angr" and rev.get("analysis_complete") is True
    complete = engine_complete and not missing and not ambiguous_calls and not non_addressed
    reasons = []
    if not engine_complete:
        reasons.append("revq engine did not certify a complete recovered function map")
    if missing:
        reasons.append("%d recovered functions omitted by node/byte budget" % missing)
    if non_addressed:
        suffix = "" if non_addressed == 1 else "s"
        subject = "it has" if non_addressed == 1 else "they have"
        reasons.append("%d recovered function record%s omitted because %s no valid address" %
                       (non_addressed, suffix, subject))
    if ambiguous_calls:
        reasons.append("%d call names resolve to multiple recovered functions" % ambiguous_calls)

    return {
        "facts": {
            "engine": rev.get("engine", "unknown"),
            "recovered_functions": total,
            "visible_functions": len(result_nodes),
            "visible_internal_edges": edges,
            "graph": result_nodes,
        },
        "coverage": {
            "complete": complete,
            "scope": "revq recovered call map (not a CFG, data-flow proof, or feasible execution path)",
            "omitted": {
                "functions": missing,
                "internal_edges_from_visible_nodes": hidden_edges,
                "ambiguous_calls_from_visible_nodes": ambiguous_calls,
                "non_addressed_functions": non_addressed,
                "indirect_calls": "unknown (revq does not enumerate them)",
            },
        },
        "diagnostics": reasons,
    }
