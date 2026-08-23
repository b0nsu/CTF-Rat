"""Structured, bounded Function Card v2 built from existing revq facts."""
from __future__ import annotations

import collections
import json
import os
import re
from typing import Any, Optional

from .artifact import get as artifact_get
from .contracts import execute

SCHEMA = "rat.function-card/v2"
COMPARE_CALLS = {"strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp", "bcmp", "wcscmp", "wcsncmp", "strstr"}
INPUT_CALLS = {"read", "recv", "scanf", "__isoc99_scanf", "sscanf", "fgets", "gets", "getline", "fread", "getchar", "fgetc"}
POSITIVE = re.compile(r"\b(?:correct|success|congrat|accepted|valid|granted|unlocked|nice|flag)\b", re.I)
NEGATIVE = re.compile(r"\b(?:wrong|incorrect|invalid|fail(?:ed|ure)?|denied|reject(?:ed)?|try\s+again)\b", re.I)


def _rat_root(root: Optional[str]) -> str:
    base = os.path.abspath(root or os.getcwd())
    return base if os.path.basename(base) == ".rat" else os.path.join(base, ".rat")


def _artifact_bytes(result: dict[str, Any], kind: str, root: str) -> bytes:
    for artifact in result.get("artifacts", []):
        if artifact.get("kind") == kind:
            return artifact_get(artifact["digest"], root=root)
    return b""


def load_revmap(binary: str, *, root: Optional[str] = None, fast: bool = False,
                timeout: float = 90) -> tuple[dict[str, Any], dict[str, Any]]:
    binary = os.path.realpath(binary)
    rat_root = _rat_root(root)
    revq = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "revq"))
    argv = [revq, binary]
    if fast:
        argv.append("--fast")
    argv.append("--json")
    result = execute(argv, root=rat_root, input_paths=[binary],
                     parameters={"query": "function-card-v2-revmap", "fast": bool(fast)},
                     timeout=timeout)
    if result.get("status") != "ok":
        raise ValueError("revq failed: %s" % result.get("status", "unknown"))
    raw = _artifact_bytes(result, "stdout", rat_root)
    try:
        rev = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("revq did not return a JSON revmap") from exc
    if not isinstance(rev, dict) or "functions" not in rev:
        raise ValueError("invalid revmap")
    return rev, result.get("provenance", {}).get("cache", {})


def _parse_int(value: str) -> Optional[int]:
    try:
        return int(value, 0)
    except (ValueError, TypeError):
        return None


def find_function(rev: dict[str, Any], target: str) -> tuple[dict[str, Any], str]:
    funcs = list(rev.get("functions", []))
    address = _parse_int(target)
    exact = [f for f in funcs if f.get("name") == target or (address is not None and f.get("addr") == address)]
    if exact:
        return exact[0], "exact"
    partial = [f for f in funcs if target.lower() in str(f.get("name", "")).lower()]
    if len(partial) == 1:
        return partial[0], "partial-unique"
    if len(partial) > 1:
        names = ", ".join(str(f.get("name")) for f in partial[:8])
        raise ValueError("ambiguous function target: %s" % names)
    raise ValueError("function not found: %s" % target)


def _oracle_kind(text: str) -> Optional[str]:
    if NEGATIVE.search(text):
        return "failure"
    if POSITIVE.search(text):
        return "success"
    return None


def _oracle_functions(rev: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    for f in rev.get("functions", []):
        for text in f.get("strings", []):
            kind = _oracle_kind(str(text))
            if kind:
                out[str(f.get("name", "?"))].append({"kind": kind, "text": str(text)[:160]})
    return dict(out)


def _oracle_distance(rev: dict[str, Any], start: str, oracle_funcs: set[str]) -> Optional[int]:
    if start in oracle_funcs:
        return 0
    graph = {str(f.get("name", "?")): [str(x) for x in f.get("calls", [])]
             for f in rev.get("functions", [])}
    queue = collections.deque([(start, 0)])
    seen = {start}
    while queue:
        name, dist = queue.popleft()
        if dist >= 6:
            continue
        for callee in graph.get(name, []):
            if callee in oracle_funcs:
                return dist + 1
            if callee not in seen and callee in graph:
                seen.add(callee)
                queue.append((callee, dist + 1))
    return None


def _role(func: dict[str, Any], oracle_strings: list[dict[str, str]], compare_calls: list[str],
          input_calls: list[str]) -> tuple[str, float, list[str]]:
    reasons = []
    if oracle_strings:
        reasons.append("references success/failure output")
    if compare_calls:
        reasons.append("calls comparison routine")
    if input_calls:
        reasons.append("reads input directly")
    if oracle_strings and compare_calls:
        return "checker", 0.9, reasons
    if input_calls and not oracle_strings:
        return "input", 0.75, reasons
    if compare_calls:
        return "compare-helper", 0.7, reasons
    if oracle_strings:
        return "decision/output", 0.7, reasons
    return "unknown", 0.25, reasons or ["no strong role signal in revq facts"]


def build_card(rev: dict[str, Any], target: str, *, binary: Optional[str] = None,
               cache: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    func, match = find_function(rev, target)
    name = str(func.get("name", target))
    calls = sorted(set(str(x) for x in func.get("calls", [])))[:24]
    callers = sorted({str(f.get("name", "?")) for f in rev.get("functions", []) if name in f.get("calls", [])})[:24]
    compare_calls = sorted(set(calls) & COMPARE_CALLS)
    input_calls = sorted(set(calls) & INPUT_CALLS)
    oracle_map = _oracle_functions(rev)
    oracle_strings = oracle_map.get(name, [])[:12]
    role, confidence, role_reasons = _role(func, oracle_strings, compare_calls, input_calls)
    distance = _oracle_distance(rev, name, set(oracle_map))

    next_queries = []
    quoted_binary = json.dumps(binary or rev.get("bin", "<bin>"))
    if role in {"checker", "compare-helper", "decision/output"}:
        next_queries.append("rat-adapt --root . --emit stdout decomp %s %s" % (quoted_binary, name))
    if oracle_strings:
        next_queries.append("inspect oracle xrefs/branch direction before symbolic find/avoid")
    if compare_calls:
        next_queries.append("trace comparison operands backward; do not infer constraints from callee name alone")
    if rev.get("evasion"):
        next_queries.append("cross-check static assumptions dynamically because evasion signals are present")
    if not next_queries:
        next_queries.append("use revq --xrefs or a named decompile only if a concrete question remains")

    return {
        "schema": SCHEMA,
        "binary": os.path.realpath(binary) if binary else rev.get("bin"),
        "revmap": {
            "engine": rev.get("engine"),
            "schema": rev.get("schema"),
            "analysis_complete": bool(rev.get("analysis_complete", False)),
            "cache": cache or {},
        },
        "function": {
            "name": name,
            "address": func.get("addr", 0),
            "size": func.get("size", 0),
            "blocks": func.get("nblocks", 0),
            "instructions": func.get("ninstr", 0),
            "count_quality": func.get("count_quality", "unknown"),
            "match": match,
        },
        "role": {"label": role, "confidence": confidence, "reasons": role_reasons},
        "callers": callers,
        "callees": calls,
        "compare_calls": compare_calls,
        "input_calls": input_calls,
        "strings": [str(x)[:160] for x in func.get("strings", [])[:16]],
        "oracle": {
            "signals": oracle_strings,
            "distance_calls": distance,
            "reachable_oracle": distance is not None,
        },
        "compare_sites": [],
        "branch_sites": [],
        "data_dependencies": [],
        "stack_dependencies": [],
        "coverage": {
            "facts": "revq function/call/string/xref-derived facts",
            "compare_sites": "not available in v2.0; compare callees only",
            "branch_sites": "not available in v2.0",
            "data_dependencies": "not available; use measured backward-slice follow-up",
            "stack_dependencies": "not available; no stack claim made",
        },
        "next": next_queries[:5],
    }


def render_text(card: dict[str, Any]) -> str:
    f = card["function"]
    role = card["role"]
    lines = [
        "== FUNCTION CARD v2 ==",
        "%s @%#x size=%s blocks=%s instr=%s" %
        (f["name"], int(f.get("address") or 0), f["size"], f["blocks"], f["instructions"]),
        "role: %s confidence=%.2f" % (role["label"], role["confidence"]),
        "callers: " + (", ".join(card["callers"]) or "-"),
        "callees: " + (", ".join(card["callees"]) or "-"),
        "compare: " + (", ".join(card["compare_calls"]) or "-"),
        "input: " + (", ".join(card["input_calls"]) or "-"),
    ]
    if card["oracle"]["signals"]:
        lines.append("oracle: " + "; ".join("%s:%s" % (x["kind"], x["text"]) for x in card["oracle"]["signals"]))
    lines.append("oracle_distance_calls: %s" % (card["oracle"]["distance_calls"] if card["oracle"]["distance_calls"] is not None else "unknown"))
    lines.append("next:")
    lines.extend("  - " + x for x in card["next"])
    return "\n".join(lines)
