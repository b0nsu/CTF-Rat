"""Bridge deterministic analysis outputs into the canonical artifact/cache index.

Legacy sidecars remain supported by callers during migration. This module only
owns content-addressed JSON artifacts plus the shared ``ratlib.cache`` index.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional

from .artifact import get as artifact_get, put_bytes
from .cache import Cache, key as cache_key

VERSION = "rat.analysis-cache/v1"
POLICY_DIGEST = "sha256:" + hashlib.sha256(b"deterministic-local-analysis/v1").hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def rat_root(subject: Optional[str] = None, root: Optional[str] = None) -> str:
    """Find the challenge .rat root without requiring every legacy CLI to grow --root."""
    if root:
        base = os.path.abspath(root)
        return base if os.path.basename(base) == ".rat" else os.path.join(base, ".rat")
    explicit = os.environ.get("RAT_CACHE_ROOT") or os.environ.get("RAT_TELEMETRY_ROOT")
    if explicit:
        base = os.path.abspath(explicit)
        return base if os.path.basename(base) == ".rat" else os.path.join(base, ".rat")

    starts = [os.getcwd()]
    if subject:
        starts.append(os.path.dirname(os.path.abspath(subject)) if os.path.isfile(subject) else os.path.abspath(subject))
    seen = set()
    for start in starts:
        cur = os.path.abspath(start)
        while cur not in seen:
            seen.add(cur)
            rr = os.path.join(cur, ".rat")
            if os.path.isdir(rr) or os.path.isfile(os.path.join(cur, "run.json")):
                return rr
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
    return os.path.join(os.path.abspath(os.getcwd()), ".rat")


def make_key(*, tool_name: str, tool_version: str, build_digest: str,
             input_digest: str, input_size: int, parameters: dict[str, Any],
             output_schema: str) -> str:
    return cache_key(
        tool={"name": tool_name, "version": tool_version, "build_digest": build_digest},
        inputs=[{"role": "input", "digest": input_digest, "size": int(input_size)}],
        parameters=parameters,
        dependencies={},
        policy_digest=POLICY_DIGEST,
        output_schema=output_schema,
    )


def _metric_read(root: str, tool: str, key: str, hit: bool, detail: Optional[str] = None) -> None:
    try:
        from .telemetry import record_cache
        record_cache(tool=tool, key=key, hit=hit, root=root, detail=detail)
    except Exception:
        pass


def _metric_write(root: str, tool: str, key: str) -> None:
    try:
        from .telemetry import record_cache_write
        record_cache_write(tool=tool, key=key, root=root)
    except Exception:
        pass


def load_json(*, root: str, tool_name: str, tool_version: str, build_digest: str,
              input_digest: str, input_size: int, parameters: dict[str, Any],
              output_schema: str, record_metric: bool = True) -> tuple[Optional[dict[str, Any]], str]:
    key = make_key(tool_name=tool_name, tool_version=tool_version, build_digest=build_digest,
                   input_digest=input_digest, input_size=input_size, parameters=parameters,
                   output_schema=output_schema)
    hit = Cache(root).get(key)
    if not hit:
        if record_metric:
            _metric_read(root, tool_name, key, False)
        return None, key
    try:
        doc = json.loads(artifact_get(hit, root=root))
        if not isinstance(doc, dict):
            raise ValueError("cached JSON is not an object")
    except Exception:
        if record_metric:
            _metric_read(root, tool_name, key, False, "indexed artifact unavailable or invalid")
        return None, key
    if record_metric:
        _metric_read(root, tool_name, key, True)
    return doc, key


def store_json(doc: dict[str, Any], *, root: str, tool_name: str, tool_version: str,
               build_digest: str, input_digest: str, input_size: int,
               parameters: dict[str, Any], output_schema: str,
               logical_name: str) -> tuple[str, str]:
    key = make_key(tool_name=tool_name, tool_version=tool_version, build_digest=build_digest,
                   input_digest=input_digest, input_size=input_size, parameters=parameters,
                   output_schema=output_schema)
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    artifact = put_bytes(raw, kind="analysis-json", media_type="application/json",
                         logical_name=logical_name, root=root,
                         provenance={"cache_key": key, "tool": tool_name})
    Cache(root).put(key, artifact["digest"])
    _metric_write(root, tool_name, key)
    return key, artifact["digest"]


def indexed(*, root: str, tool_name: str, tool_version: str, build_digest: str,
            input_digest: str, input_size: int, parameters: dict[str, Any],
            output_schema: str) -> bool:
    """Cheap index presence check for routing/status UIs; emits no telemetry."""
    key = make_key(tool_name=tool_name, tool_version=tool_version, build_digest=build_digest,
                   input_digest=input_digest, input_size=input_size, parameters=parameters,
                   output_schema=output_schema)
    return Cache(root).get(key) is not None
