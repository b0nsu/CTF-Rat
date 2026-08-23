"""Low-overhead benchmark telemetry for CTF-Rat.

Telemetry is opt-in. ``begin()`` creates ``.rat/telemetry/active.json`` and
subsequent record helpers append compact JSONL events to the selected run.
Without an active run the helpers are no-ops, so production solving behavior is
unchanged unless measurement is explicitly enabled.
"""
from __future__ import annotations

import collections
import fcntl
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _epoch_ms() -> int:
    return time.time_ns() // 1_000_000


def _rat_root(root: Optional[str]) -> str:
    root = os.path.abspath(root or os.getcwd())
    return root if os.path.basename(root) == ".rat" else os.path.join(root, ".rat")


def _telemetry_dir(rat_root: str) -> str:
    return os.path.join(rat_root, "telemetry")


def _active_path(rat_root: str) -> str:
    return os.path.join(_telemetry_dir(rat_root), "active.json")


def _event_path(rat_root: str, run_id: str) -> str:
    return os.path.join(_telemetry_dir(rat_root), "runs", run_id + ".jsonl")


def _write_json_atomic(path: str, doc: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp.%d.%s" % (os.getpid(), uuid.uuid4().hex[:8])
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_json(path: str) -> Optional[dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def _discover_rat_root(start: Optional[str] = None) -> Optional[str]:
    explicit = os.environ.get("RAT_TELEMETRY_ROOT")
    if explicit:
        rr = _rat_root(explicit)
        if os.path.isfile(_active_path(rr)):
            return rr
    cur = os.path.abspath(start or os.getcwd())
    if os.path.isfile(cur):
        cur = os.path.dirname(cur)
    while True:
        rr = cur if os.path.basename(cur) == ".rat" else os.path.join(cur, ".rat")
        if os.path.isfile(_active_path(rr)):
            return rr
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def active(root: Optional[str] = None) -> Optional[dict[str, Any]]:
    rr = _rat_root(root) if root is not None else _discover_rat_root()
    if rr is None:
        return None
    doc = _read_json(_active_path(rr))
    if not doc or not RUN_ID_RE.match(str(doc.get("run_id", ""))):
        return None
    out = dict(doc)
    out["rat_root"] = rr
    return out


def active_run_id(root: Optional[str] = None) -> Optional[str]:
    doc = active(root)
    return str(doc["run_id"]) if doc else None


def _append(path: str, doc: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    line = (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "ab", closefd=False) as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(line)
            f.flush()
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        os.close(fd)


def begin(root: str, *, run_id: Optional[str] = None, ablation_id: str = "A0",
          challenge_id: Optional[str] = None, attempt: int = 1, eligible: bool = True,
          model: Optional[str] = None, force: bool = False) -> dict[str, Any]:
    rr = _rat_root(root)
    current = _read_json(_active_path(rr))
    if current and not force:
        raise ValueError("telemetry run already active: %s" % current.get("run_id", "?"))
    run_id = run_id or ("run_" + uuid.uuid4().hex[:16])
    if not RUN_ID_RE.match(run_id):
        raise ValueError("invalid run_id")
    if ablation_id not in {"A0", "A1", "A2", "A3", "A4", "A5"}:
        raise ValueError("invalid ablation_id")
    if not isinstance(attempt, int) or attempt < 1:
        raise ValueError("attempt must be >= 1")
    root_abs = os.path.abspath(root)
    default_challenge = (os.path.basename(os.path.dirname(root_abs)) if os.path.basename(root_abs) == ".rat"
                         else os.path.basename(root_abs))
    challenge_id = challenge_id or default_challenge or "challenge"
    meta = {
        "schema": "rat.telemetry-run/v1",
        "run_id": run_id,
        "ablation_id": ablation_id,
        "challenge_id": challenge_id,
        "attempt": attempt,
        "eligible": bool(eligible),
        "model": model,
        "started_at": _iso(),
        "started_ms": _epoch_ms(),
    }
    _write_json_atomic(_active_path(rr), meta)
    _append(_event_path(rr, run_id), {"type": "begin", **meta})
    return {**meta, "rat_root": rr}


def record(event_type: str, payload: Optional[dict[str, Any]] = None, *,
           root: Optional[str] = None, run_id: Optional[str] = None) -> bool:
    if not isinstance(event_type, str) or not event_type:
        raise ValueError("event_type is required")
    rr = _rat_root(root) if root is not None else _discover_rat_root()
    if rr is None:
        return False
    current = _read_json(_active_path(rr))
    selected = run_id or (str(current.get("run_id")) if current else None)
    if not selected or not RUN_ID_RE.match(selected):
        return False
    ev = {
        "type": event_type,
        "run_id": selected,
        "ts": _iso(),
        "ts_ms": _epoch_ms(),
        **(payload or {}),
    }
    _append(_event_path(rr, selected), ev)
    return True


def _normalize_argv(argv: Sequence[str], cwd: Optional[str] = None) -> list[str]:
    if not argv:
        return []
    base = os.path.abspath(cwd or os.getcwd())
    out = [os.path.basename(argv[0])]
    for arg in argv[1:]:
        if not isinstance(arg, str):
            out.append(str(arg))
            continue
        candidate = arg if os.path.isabs(arg) else os.path.join(base, arg)
        if os.path.exists(candidate):
            out.append(os.path.realpath(candidate))
        else:
            out.append(arg)
    return out


def record_tool(argv: Sequence[str], *, duration_ms: int, exit_code: int,
                stdout_bytes: int = 0, stderr_bytes: int = 0,
                cwd: Optional[str] = None, root: Optional[str] = None) -> bool:
    normalized = _normalize_argv(argv, cwd)
    raw = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode()
    import hashlib
    fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
    return record("tool", {
        "argv": normalized,
        "tool": normalized[0] if normalized else "?",
        "fingerprint": fingerprint,
        "duration_ms": max(0, int(duration_ms)),
        "exit_code": int(exit_code),
        "stdout_bytes": max(0, int(stdout_bytes)),
        "stderr_bytes": max(0, int(stderr_bytes)),
    }, root=root)


def record_cache(*, tool: str, key: str, hit: bool, root: Optional[str] = None,
                 detail: Optional[str] = None) -> bool:
    payload: dict[str, Any] = {"tool": tool, "key": key, "hit": bool(hit), "action": "read"}
    if detail:
        payload["detail"] = detail
    return record("cache", payload, root=root)


def record_cache_write(*, tool: str, key: str, root: Optional[str] = None) -> bool:
    return record("cache", {"tool": tool, "key": key, "action": "write"}, root=root)


def record_model(*, input_tokens: int = 0, output_tokens: int = 0,
                 cache_read_tokens: int = 0, cache_creation_tokens: int = 0,
                 context_tokens: Optional[int] = None, duration_ms: int = 0,
                 model: Optional[str] = None, root: Optional[str] = None) -> bool:
    payload: dict[str, Any] = {
        "input_tokens": max(0, int(input_tokens)),
        "output_tokens": max(0, int(output_tokens)),
        "cache_read_tokens": max(0, int(cache_read_tokens)),
        "cache_creation_tokens": max(0, int(cache_creation_tokens)),
        "duration_ms": max(0, int(duration_ms)),
    }
    if context_tokens is not None:
        payload["context_tokens"] = max(0, int(context_tokens))
    if model:
        payload["model"] = model
    return record("model", payload, root=root)


def finish(root: str, *, status: str = "completed", outcome: str = "unknown",
           verified: bool = False, flag_found: bool = False) -> dict[str, Any]:
    rr = _rat_root(root)
    current = _read_json(_active_path(rr))
    if not current:
        raise ValueError("no active telemetry run")
    run_id = str(current["run_id"])
    if status not in {"completed", "timeout", "partial", "infra-failure", "skipped"}:
        raise ValueError("invalid benchmark status")
    if outcome not in {"verified", "solve-claimed", "failed", "censored", "unknown", "skipped"}:
        raise ValueError("invalid benchmark outcome")
    verified = bool(verified or outcome == "verified")
    payload = {
        "status": status,
        "outcome": outcome,
        "verified": verified,
        "flag_found": bool(flag_found),
        "finished_at": _iso(),
        "finished_ms": _epoch_ms(),
    }
    record("finish", payload, root=rr, run_id=run_id)
    try:
        os.unlink(_active_path(rr))
    except FileNotFoundError:
        pass
    return {"run_id": run_id, **payload}


def _events(rat_root: str, run_id: str) -> list[dict[str, Any]]:
    path = _event_path(rat_root, run_id)
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if isinstance(ev, dict):
                    out.append(ev)
    except OSError:
        pass
    return out


def _select_run(rat_root: str, run_id: Optional[str]) -> str:
    if run_id:
        if not RUN_ID_RE.match(run_id):
            raise ValueError("invalid run_id")
        return run_id
    current = _read_json(_active_path(rat_root))
    if current and RUN_ID_RE.match(str(current.get("run_id", ""))):
        return str(current["run_id"])
    runs = os.path.join(_telemetry_dir(rat_root), "runs")
    try:
        names = [n for n in os.listdir(runs) if n.endswith(".jsonl")]
        if names:
            latest = max(names, key=lambda n: os.path.getmtime(os.path.join(runs, n)))
            return latest[:-6]
    except OSError:
        pass
    raise ValueError("no telemetry run found")


def summarize(root: str, run_id: Optional[str] = None) -> dict[str, Any]:
    rr = _rat_root(root)
    selected = _select_run(rr, run_id)
    events = _events(rr, selected)
    if not events:
        raise ValueError("telemetry run has no events")
    begin_ev = next((e for e in events if e.get("type") == "begin"), {})
    finish_ev = next((e for e in reversed(events) if e.get("type") == "finish"), {})
    tools = [e for e in events if e.get("type") == "tool"]
    counts = collections.Counter(str(e.get("fingerprint", "")) for e in tools if e.get("fingerprint"))
    tool_names = collections.Counter(str(e.get("tool", "?")) for e in tools)
    by_fp: dict[str, dict[str, Any]] = {}
    for ev in tools:
        fp = str(ev.get("fingerprint", ""))
        if fp and fp not in by_fp:
            by_fp[fp] = ev
    duplicate_calls = sum(max(0, n - 1) for n in counts.values())
    top_duplicates = []
    for fp, count in counts.most_common():
        if count <= 1:
            continue
        ev = by_fp[fp]
        top_duplicates.append({"count": count, "tool": ev.get("tool"), "argv": ev.get("argv")})
        if len(top_duplicates) >= 10:
            break

    cache = [e for e in events if e.get("type") == "cache"]
    cache_reads = [e for e in cache if e.get("action") == "read"]
    cache_hits = sum(1 for e in cache_reads if e.get("hit") is True)
    cache_misses = sum(1 for e in cache_reads if e.get("hit") is False)
    cache_writes = sum(1 for e in cache if e.get("action") == "write")

    model_events = [e for e in events if e.get("type") == "model"]
    def total(field: str) -> int:
        return sum(int(e.get(field, 0) or 0) for e in model_events)
    contexts = [int(e["context_tokens"]) for e in model_events if e.get("context_tokens") is not None]

    start_ms = int(begin_ev.get("started_ms", events[0].get("ts_ms", 0)) or 0)
    end_ms = int(finish_ev.get("finished_ms", events[-1].get("ts_ms", start_ms)) or start_ms)
    flag_ev = next((e for e in events if e.get("flag_found") is True), None)
    verified_ev = next((e for e in events if e.get("verified") is True), None)
    flag_ms = int(flag_ev.get("ts_ms", flag_ev.get("finished_ms", 0))) if flag_ev else 0
    verified_ms = int(verified_ev.get("ts_ms", verified_ev.get("finished_ms", 0))) if verified_ev else 0

    metrics = {
        "verified_solve": bool(finish_ev.get("verified") or verified_ev),
        "flag_found": bool(finish_ev.get("flag_found") or flag_ev),
        "time_to_flag_ms": (max(0, flag_ms - start_ms) if flag_ms else None),
        "time_to_verified_ms": (max(0, verified_ms - start_ms) if verified_ms else None),
        "wall_time_ms": max(0, end_ms - start_ms),
        "peak_context_tokens": max(contexts) if contexts else None,
        "tokens": {
            "input": total("input_tokens"),
            "output": total("output_tokens"),
            "cache_read": total("cache_read_tokens"),
            "cache_creation": total("cache_creation_tokens"),
        },
        "tools": {
            "calls": len(tools),
            "duplicate_calls": duplicate_calls,
            "counts": dict(sorted(tool_names.items())),
            "top_duplicates": top_duplicates,
            "wall_ms": sum(int(e.get("duration_ms", 0) or 0) for e in tools),
        },
        "cache": {
            "reads": len(cache_reads),
            "hits": cache_hits,
            "misses": cache_misses,
            "writes": cache_writes,
            "hit_ratio": (cache_hits / len(cache_reads) if cache_reads else None),
        },
        "model": {
            "name": begin_ev.get("model"),
            "events": len(model_events),
            "wall_ms": total("duration_ms"),
        },
        "deep_escalations": sum(1 for e in events if e.get("type") == "deep"),
    }
    doc = {
        "schema": "rat.benchmark-result/v1",
        "benchmark_run_id": selected,
        "ablation_id": begin_ev.get("ablation_id", "A0"),
        "challenge_id": begin_ev.get("challenge_id", "challenge"),
        "attempt": int(begin_ev.get("attempt", 1) or 1),
        "status": finish_ev.get("status", "partial"),
        "eligible": bool(begin_ev.get("eligible", True)),
        "outcome": finish_ev.get("outcome", "unknown"),
        "started_at": begin_ev.get("started_at", events[0].get("ts")),
        "finished_at": finish_ev.get("finished_at", events[-1].get("ts")),
        "metrics": metrics,
        "oracle": {"verified": metrics["verified_solve"], "flag_found": metrics["flag_found"]},
        "ground_truth": {},
    }
    from .schema import validate
    validate(doc, "rat.benchmark-result/v1")
    return doc
