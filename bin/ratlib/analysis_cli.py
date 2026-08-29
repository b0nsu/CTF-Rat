"""CLI adapter for ratlib.analysis with invocation telemetry persistence.

The analysis engine already emits canonical ``rat.tool-result/v1`` envelopes.
Standalone ``rat-*`` wrappers historically printed those envelopes without
persisting them, so ``rat-metrics`` could not count real analysis invocations.
This adapter records the existing envelope in the canonical artifact store
before preserving the original CLI output/exit behavior.
"""
from __future__ import annotations

import json
import copy

from . import analysis
from .artifact import put_bytes
from .schema import validate


def _persist_invocation(doc, args):
    """Best-effort persist one valid analysis envelope for session telemetry.

    Telemetry storage must not turn an otherwise valid analysis result into a
    tool failure. Invalid envelopes are not recorded as trustworthy telemetry;
    the underlying CLI keeps its pre-existing behavior.
    """
    try:
        exit_info = doc.get("exit") or {}
        if doc.get("status") not in {"ok", "partial"} or exit_info.get("code") != 0:
            return
        doc = copy.deepcopy(doc)
        if doc.get("cache_state") is None:
            doc["cache_state"] = "bypass"
            provenance = doc.setdefault("provenance", {})
            cache = provenance.setdefault("cache", {})
            cache["state"] = "bypass"
        validate(doc)
        store = analysis.root(args, getattr(args, "binary", None))
        raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        name = (doc.get("tool", {}) or {}).get("name") or "rat-analysis"
        put_bytes(raw, kind="tool-result", media_type="application/json",
                  logical_name=name + "-invocation.json", root=store)
    except Exception:
        return


def run(entrypoint, *args, **kwargs):
    """Run an analysis-family entrypoint while recording emitted tool results."""
    original_emit = analysis.emit

    def emit_and_record(doc, parsed_args):
        _persist_invocation(doc, parsed_args)
        return original_emit(doc, parsed_args)

    analysis.emit = emit_and_record
    try:
        return entrypoint(*args, **kwargs)
    finally:
        analysis.emit = original_emit


def main(tool_name):
    """Compatibility adapter for wrappers that delegate to analysis.main()."""
    return run(analysis.main, tool_name)
