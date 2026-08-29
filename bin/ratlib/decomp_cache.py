"""Content/provenance keys for the legacy shell decompiler cache."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone


SCHEMA = "rat.decomp-cache/v1"
_INVOCATION_POLICY = "sha256:" + hashlib.sha256(b"decomp-local-ghidra-v1").hexdigest()


def _register_index(cache: str, prov: dict, binary: str) -> None:
    """Best-effort registration in the shared canonical cache index.

    The existing provenance key (`cache_key(prov)`) stays the source of
    truth for hit/stale/partial here; this only makes that decision
    observable through the same index revq/rat-profile use. Anchoring the
    root off the binary (via the shared resolver) is what makes "one index"
    actually hold across all three tools.

    `envelope_digest` pins the produced artifact by content (the `_index.txt`
    export listing) so the lineage row survives deletion or staling of the
    mutable `path`; without it a dropped cache dir leaves a dangling row that
    can't be told from a live one.
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
        from ratlib.cache import Cache, resolve_index_root
        idx_root = resolve_index_root(binary)
        index_txt = os.path.join(cache, "_index.txt")
        env_digest = "sha256:" + sha256(index_txt) if os.path.isfile(index_txt) else None
        Cache(idx_root).put_entry("sha256:" + cache_key(prov), backend="decomp_dir",
                                  path=cache, envelope_digest=env_digest)
    except Exception:
        pass


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ghidra_version(home: str) -> str:
    props = os.path.join(home, "Ghidra", "application.properties")
    try:
        with open(props, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "unavailable"


def provenance(binary: str, ghidra_home: str, script_dir: str) -> dict:
    scripts = {}
    for name in ("DecompExport.java", "DecompOne.java"):
        path = os.path.join(script_dir, name)
        scripts[name] = sha256(path) if os.path.isfile(path) else "missing"
    return {
        "binary_sha256": sha256(binary),
        "ghidra_version": ghidra_version(ghidra_home),
        "scripts": scripts,
        "analyzer_options": {"project": "ephemeral", "auto_analysis": True, "language": "auto", "compiler": "auto"},
    }


def cache_key(prov: dict) -> str:
    raw = json.dumps(prov, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def load_meta(cache: str):
    try:
        with open(os.path.join(cache, ".rat-cache.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def validate(cache: str, binary: str, ghidra_home: str, script_dir: str) -> tuple[bool, str]:
    meta = load_meta(cache)
    if not meta:
        return False, "legacy"
    prov = provenance(binary, ghidra_home, script_dir)
    if meta.get("schema") != SCHEMA or meta.get("key") != cache_key(prov):
        return False, "stale"
    if meta.get("status") != "complete" or not os.path.isfile(os.path.join(cache, "_index.txt")):
        return False, "partial"
    _register_index(cache, prov, binary)
    return True, "hit"


def write_meta(cache: str, binary: str, ghidra_home: str, script_dir: str, status: str, diagnostics: str = "") -> None:
    prov = provenance(binary, ghidra_home, script_dir)
    index = os.path.join(cache, "_index.txt")
    total = 0
    if os.path.isfile(index):
        with open(index, encoding="utf-8", errors="replace") as f:
            total = sum(1 for line in f if line.strip())
    exported = total; discovered = total; failed = []
    try:
        with open(os.path.join(cache, ".rat-decomp-status.json"), encoding="utf-8") as f: export_status=json.load(f)
        discovered=int(export_status.get("discovered", total)); exported=int(export_status.get("exported", total)); failed=list(export_status.get("failed", []))
    except (OSError, ValueError, TypeError):
        pass
    if failed or exported != discovered:
        status="partial"
        diagnostics=diagnostics or "function export incomplete"
    payload = {
        "schema": SCHEMA, "key": cache_key(prov), "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(), "provenance": prov,
        "functions_total": discovered, "functions_exported": exported,
        "failed_functions": failed, "diagnostics": [diagnostics] if diagnostics else [],
    }
    os.makedirs(cache, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".rat-cache-", suffix=".tmp", dir=cache)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True, indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, os.path.join(cache, ".rat-cache.json"))
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    if payload["status"] == "complete":
        _register_index(cache, prov, binary)


def record_invocation(cache: str, binary: str, ghidra_home: str, script_dir: str,
                      cache_state: str, status: str, operation: str, requested: str,
                      started_at: str, started_ns: int) -> bool:
    """Persist one successful decomp CLI invocation using the canonical tool-result stream.

    The mutable decomp directory remains the cache source of truth.  This record is
    observational only: every CLI invocation gets a unique id while cache identity
    stays input/provenance-derived, so a warm hit cannot disappear into one index row.
    """
    try:
        if cache_state not in {"hit", "miss", "bypass"}:
            raise ValueError("invalid cache state")
        if status not in {"ok", "partial"}:
            raise ValueError("invalid successful result status")
        if operation not in {"list", "function"}:
            raise ValueError("invalid operation")
        prov = provenance(binary, ghidra_home, script_dir)
        meta = load_meta(cache) or {}
        finished = datetime.now(timezone.utc).isoformat()
        duration_ms = max(0, (time.monotonic_ns() - int(started_ns)) // 1_000_000)
        invocation_id = "invoke_" + uuid.uuid4().hex
        tool_path = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "decomp"))
        dependency_versions = {"ghidra": prov["ghidra_version"]}
        dependency_versions.update({"script:" + name: digest for name, digest in sorted(prov["scripts"].items())})
        doc = {
            "schema": "rat.tool-result/v1",
            "tool": {"name": "decomp", "version": "1", "build_digest": "sha256:" + sha256(tool_path)},
            "run_id": invocation_id,
            "invocation_id": invocation_id,
            "status": status,
            "started_at": started_at,
            "finished_at": finished,
            "duration_ms": int(duration_ms),
            "inputs": [{"role": "binary", "digest": "sha256:" + prov["binary_sha256"]}],
            "parameters": {"operation": operation, "requested": requested or None},
            "summary": {
                "cache_status": meta.get("status"),
                "functions_total": meta.get("functions_total"),
                "functions_exported": meta.get("functions_exported"),
            },
            "artifacts": [],
            "findings": [],
            "diagnostics": [],
            "exit": {"code": 0, "signal": None, "timed_out": False, "cancelled": False},
            "provenance": {
                "platform": sys.platform,
                "dependency_versions": dependency_versions,
                "policy_digest": _INVOCATION_POLICY,
                "cache": {"state": cache_state, "key": "sha256:" + cache_key(prov)},
            },
            "cache_state": cache_state,
        }
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
        from ratlib.artifact import put_bytes
        from ratlib.cache import resolve_index_root
        from ratlib.schema import validate as validate_schema
        validate_schema(doc, "rat.tool-result/v1")
        payload = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        put_bytes(payload, kind="tool-result", media_type="application/json",
                  logical_name="decomp-%s.json" % invocation_id,
                  root=resolve_index_root(binary),
                  provenance={"tool": "decomp", "invocation_id": invocation_id})
        return True
    except Exception:
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("key", "validate", "write"):
        sp = sub.add_parser(name)
        sp.add_argument("cache"); sp.add_argument("binary"); sp.add_argument("ghidra_home"); sp.add_argument("script_dir")
        if name == "write":
            sp.add_argument("status", choices=("complete", "partial")); sp.add_argument("--diagnostic", default="")
    sp = sub.add_parser("invocation")
    sp.add_argument("cache"); sp.add_argument("binary"); sp.add_argument("ghidra_home"); sp.add_argument("script_dir")
    sp.add_argument("cache_state", choices=("hit", "miss", "bypass"))
    sp.add_argument("status", choices=("ok", "partial"))
    sp.add_argument("operation", choices=("list", "function"))
    sp.add_argument("requested")
    sp.add_argument("started_at")
    sp.add_argument("started_ns", type=int)
    a = p.parse_args(argv)
    if a.cmd == "key":
        print(cache_key(provenance(a.binary, a.ghidra_home, a.script_dir))); return 0
    if a.cmd == "validate":
        valid, reason = validate(a.cache, a.binary, a.ghidra_home, a.script_dir)
        print(reason); return 0 if valid else {"legacy": 10, "stale": 11, "partial": 12}[reason]
    if a.cmd == "invocation":
        record_invocation(a.cache, a.binary, a.ghidra_home, a.script_dir,
                          a.cache_state, a.status, a.operation, a.requested,
                          a.started_at, a.started_ns)
        return 0
    write_meta(a.cache, a.binary, a.ghidra_home, a.script_dir, a.status, a.diagnostic); return 0


if __name__ == "__main__":
    raise SystemExit(main())