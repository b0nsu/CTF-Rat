"""Read-only session telemetry aggregator.

Reads tool-result envelopes from a .rat artifact store plus the authoritative
typed STATE v2 stream, with legacy STATE.jsonl fallback for pre-v2 sessions,
and emits one rat.session-metrics/v1 jsonl line. No binary execution, no network.
"""
from __future__ import annotations
import argparse, hashlib, json, os, sys
from datetime import datetime
from .artifact import get as artifact_get
from .completion import completion_gate
from .state_v2 import Stream

def iter_tool_results(root):
    meta_base = os.path.join(root, "metadata", "sha256")
    if not os.path.isdir(meta_base):
        return
    for a in sorted(os.listdir(meta_base)):
        sub = os.path.join(meta_base, a)
        if not os.path.isdir(sub):
            continue
        for name in sorted(os.listdir(sub)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(sub, name), encoding="utf-8") as f:
                    rec = json.load(f)
            except (OSError, ValueError):
                continue
            if rec.get("kind") != "tool-result":
                continue
            try:
                doc = json.loads(artifact_get(rec["digest"], root=root))
            except Exception:
                continue
            if doc.get("schema") == "rat.tool-result/v1":
                yield doc

def operation_fingerprint(doc):
    """sha256 over tool build + inputs + normalized params + deps + policy + output schema."""
    tool = doc.get("tool", {}) or {}
    provenance = doc.get("provenance", {}) or {}
    key = {
        "tool": {"name": tool.get("name"), "build_digest": tool.get("build_digest")},
        "inputs": sorted(i.get("digest", "") for i in doc.get("inputs", []) or []),
        "parameters": doc.get("parameters", {}) or {},
        "dependencies": provenance.get("dependency_versions", {}) or {},
        "policy_digest": provenance.get("policy_digest"),
        "output_schema": doc.get("schema"),
    }
    raw = json.dumps(key, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def guard_started_at(ctf_home, chal=None):
    try:
        with open(os.path.join(ctf_home, "ACTIVE.json"), encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError):
        return None
    if chal and obj.get("chal") != chal:
        return None
    return obj.get("started_at")

def _first_primitive_pass_ts_v2(state_dir):
    """Timestamp of the earliest STILL-ACTIVE primitive PASS, never a stale one.

    A raw scan for any "status":"pass" event is not enough: _materialize() stales
    a primitive whose self_evidence was later invalidated (evidence.invalidated),
    and a solved-then-invalidated primitive must not count as a solve for
    benchmarking/gating. Only primitive_ids whose MATERIALIZED status is
    currently pass/consumed contribute; for those, use the timestamp of their
    most recent pass transition (an earlier pass invalidated before this one is
    not the current valid primitive time).
    """
    try:
        stream = Stream(state_dir)
        events = stream.read()
        view = stream._materialize(events)
    except (OSError, ValueError):
        return None
    active_ids = {pid for pid, p in view["primitives"].items() if p.get("status") in ("pass", "consumed")}
    if not active_ids:
        return None
    latest_pass_ts = {}
    for e in events:
        if e.get("type") != "primitive.revised":
            continue
        p = e.get("payload", {})
        pid = p.get("primitive_id")
        if pid not in active_ids or p.get("status") != "pass":
            continue
        try:
            ts = int(datetime.fromisoformat(e["at"]).timestamp())
        except (KeyError, ValueError):
            continue
        if pid not in latest_pass_ts or ts > latest_pass_ts[pid]:
            latest_pass_ts[pid] = ts
    return min(latest_pass_ts.values()) if latest_pass_ts else None

def _first_primitive_pass_ts_legacy(state_dir):
    path = os.path.join(state_dir, "STATE.jsonl")
    best = None
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("t") == "primitive" and e.get("status") == "pass":
                    ts = e.get("ts")
                    if isinstance(ts, int) and (best is None or ts < best):
                        best = ts
    except OSError:
        return None
    return best

def first_primitive_pass_ts(state_dir):
    """Typed STATE v2 is the authoritative PASS gate (>=3 active direct SELF
    observations, enforced by ratlib.state_v2.revise_primitive) -- prefer it.
    Legacy STATE.jsonl is only consulted for pre-v2 sessions that never wrote
    a v2 stream; the legacy `state primitive ... pass` command is rejected.

    Once a v2 stream exists it is authoritative: a session that wrote typed
    events but has no typed PASS has NOT passed, so we must not silently fall
    back to a legacy PASS. Legacy is consulted only when no v2 stream existed.
    """
    if os.path.exists(Stream(state_dir).path):
        return _first_primitive_pass_ts_v2(state_dir)
    return _first_primitive_pass_ts_legacy(state_dir)

def first_verified_solve_ts(state_dir):
    """Timestamp of the authenticated, currently-active verified solve.

    The canonical completion gate re-authenticates the immutable rat-verify
    report and checks its primitive/exploit-task lineage. Only the matching
    verification.recorded event is eligible for solve latency; primitive PASS
    alone deliberately returns None here.
    """
    try:
        events = Stream(state_dir).read()
    except (OSError, ValueError):
        return None
    for event in events:
        if event.get("type") != "verification.recorded":
            continue
        verification_id = event.get("payload", {}).get("verification_id")
        if not verification_id:
            continue
        if completion_gate(state_dir, verification_id=verification_id).get("verified") is not True:
            continue
        try:
            return int(datetime.fromisoformat(event["at"]).timestamp())
        except (KeyError, ValueError):
            return None
    return None

def index_backends(root):
    """Distinct cached artifacts per backend from the canonical cache index.

    Closes a lineage blind spot: the tool-result-derived counts below only see
    tools that route through the bounded adapter (contracts.execute), so
    revq/decomp/pwngadget -- which write their own caches and register in the
    shared index instead -- were invisible to telemetry. The index carries one
    row per distinct (tool, inputs, params) result, so this is a floor on tool
    activity (cache hits collapse onto the same row), reported separately from
    the invocation counts rather than conflated with them.
    """
    try:
        from .cache import Cache
        return Cache(root).stats().get("by_backend", {})
    except Exception:
        return {}

def _elapsed_seconds(started_at, finished_at):
    if isinstance(started_at, int) and isinstance(finished_at, int) and finished_at >= started_at:
        return finished_at - started_at
    return None

def aggregate(docs, *, guard_started_at=None, primitive_pass_at=None,
              verified_solve_at=None, verify_pass_at=None, index_backend_counts=None):
    """Aggregate telemetry without conflating primitive proof with solved state.

    ``verify_pass_at`` retains its v1 meaning as a compatibility alias for the
    primitive-PASS timestamp. New callers should pass ``primitive_pass_at``
    and ``verified_solve_at`` explicitly. ``time_to_flag_sec`` retains its v1
    primitive-PASS meaning; verified-solve latency is exposed separately.
    """
    docs = list(docs)
    seen_fingerprints = {}
    duplicate = 0
    cache_hits = cache_misses = 0
    tool_name_counts = {}
    duration_total = 0
    for doc in docs:
        status = doc.get("status")
        cache_state = doc.get("cache_state")
        if cache_state is None:
            cache_state = "hit" if (doc.get("provenance", {}) or {}).get("cache", {}).get("hit") else "miss"
        is_hit = cache_state == "hit" and status == "ok"
        if is_hit:
            cache_hits += 1
        else:
            cache_misses += 1
            fp = operation_fingerprint(doc)
            if fp in seen_fingerprints:
                duplicate += 1
            seen_fingerprints[fp] = seen_fingerprints.get(fp, 0) + 1
        name = doc.get("tool_name") or (doc.get("tool", {}) or {}).get("name", "")
        tool_name_counts[name] = tool_name_counts.get(name, 0) + 1
        duration_total += doc.get("duration_ms", 0) or 0
    cache_requests = cache_hits + cache_misses
    if primitive_pass_at is None and verify_pass_at is not None:
        primitive_pass_at = verify_pass_at
    time_to_first_valid_primitive_sec = _elapsed_seconds(guard_started_at, primitive_pass_at)
    time_to_verified_solve_sec = _elapsed_seconds(guard_started_at, verified_solve_at)
    ghidra_runs = sum(n for name, n in tool_name_counts.items() if "ghidra" in name.lower())
    revq_runs = tool_name_counts.get("revq", 0)
    functions_decompiled = tool_name_counts.get("decomp", 0)
    return {
        "schema": "rat.session-metrics/v1",
        "tool_calls": len(docs),
        "duplicate_tool_calls": duplicate,
        "cache_requests": cache_requests,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "cache_hit_ratio": (cache_hits / cache_requests) if cache_requests else None,
        "time_to_first_valid_primitive_sec": time_to_first_valid_primitive_sec,
        "time_to_verified_solve_sec": time_to_verified_solve_sec,
        "time_to_flag_sec": time_to_first_valid_primitive_sec,
        "functions_decompiled": functions_decompiled,
        "ghidra_runs": ghidra_runs,
        "revq_runs": revq_runs,
        "duration_ms_total": duration_total,
        # lineage floor for tools that bypass the tool-result store (revq/decomp/
        # pwngadget), sourced from the shared cache index -- see index_backends().
        "indexed_artifacts_by_backend": dict(index_backend_counts) if index_backend_counts else {},
    }

def main(argv=None):
    ap = argparse.ArgumentParser(prog="rat-metrics")
    ap.add_argument("--root", help=".rat artifact store root (default: ./.rat)")
    ap.add_argument("--state-dir", help="directory containing .rat/events/STATE.v2.jsonl (legacy STATE.jsonl fallback; default: cwd)")
    ap.add_argument("--ctf-home", help="repo root for ACTIVE.json lookup (default: $CTF_HOME)")
    ap.add_argument("--chal", help="expected active challenge name for guard-begin lookup")
    ns = ap.parse_args(argv)
    root = os.path.abspath(ns.root or os.path.join(os.getcwd(), ".rat"))
    state_dir = os.path.abspath(ns.state_dir or os.getcwd())
    ctf_home = os.path.abspath(ns.ctf_home or os.environ.get(
        "CTF_HOME", os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")))
    metrics = aggregate(
        iter_tool_results(root),
        guard_started_at=guard_started_at(ctf_home, ns.chal),
        primitive_pass_at=first_primitive_pass_ts(state_dir),
        verified_solve_at=first_verified_solve_ts(state_dir),
        index_backend_counts=index_backends(root),
    )
    print(json.dumps(metrics, sort_keys=True, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
