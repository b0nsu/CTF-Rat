"""Content/provenance keys for the legacy shell decompiler cache."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone


SCHEMA = "rat.decomp-cache/v1"


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


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("key", "validate", "write"):
        sp = sub.add_parser(name)
        sp.add_argument("cache"); sp.add_argument("binary"); sp.add_argument("ghidra_home"); sp.add_argument("script_dir")
        if name == "write":
            sp.add_argument("status", choices=("complete", "partial")); sp.add_argument("--diagnostic", default="")
    a = p.parse_args(argv)
    if a.cmd == "key":
        print(cache_key(provenance(a.binary, a.ghidra_home, a.script_dir))); return 0
    if a.cmd == "validate":
        valid, reason = validate(a.cache, a.binary, a.ghidra_home, a.script_dir)
        print(reason); return 0 if valid else {"legacy": 10, "stale": 11, "partial": 12}[reason]
    write_meta(a.cache, a.binary, a.ghidra_home, a.script_dir, a.status, a.diagnostic); return 0


if __name__ == "__main__":
    raise SystemExit(main())
