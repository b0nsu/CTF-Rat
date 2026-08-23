"""Deterministic read projection of CTF-Rat state and artifacts for Desktop.

STATE v2 and the existing content-addressed artifact store remain canonical.
This module adds bounded projections only; it never creates a second database.
"""
from __future__ import annotations
import base64, json, os
from collections import Counter
from typing import Any

from .artifact import get as artifact_get, metadata as artifact_metadata
from .state_v2 import Stream, cursor

SNAPSHOT_SCHEMA = "rat.desktop.snapshot/v1"
EVENTS_SCHEMA = "rat.desktop.events/v1"
ARTIFACTS_SCHEMA = "rat.desktop.artifacts/v1"
PREVIEW_SCHEMA = "rat.desktop.artifact-preview/v1"
TELEMETRY_SCHEMA = "rat.desktop.telemetry/v1"
MAX_ARTIFACTS = 2000
MAX_PREVIEW = 256 * 1024


def _manifest(challenge_root: str) -> dict[str, Any] | None:
    path = os.path.join(os.path.abspath(challenge_root), "run.json")
    try:
        with open(path, encoding="utf-8") as source:
            doc = json.load(source)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def snapshot(challenge_root: str, *, until_seq: int | None = None) -> dict[str, Any]:
    """Return a materialized view, optionally at a historical event sequence."""
    root = os.path.abspath(challenge_root)
    stream = Stream(root)
    events = stream.read()
    if until_seq is not None and (not isinstance(until_seq, int) or until_seq < 0):
        raise ValueError("until_seq must be a non-negative integer")
    visible = events if until_seq is None else [event for event in events if event["seq"] <= until_seq]
    latest = cursor(visible[-1]) if visible else {"stream_id": events[0]["stream_id"] if events else None, "seq": 0}
    return {
        "schema": SNAPSHOT_SCHEMA,
        "challenge_root": root,
        "run": _manifest(root),
        "cursor": latest,
        "event_count": len(visible),
        "total_event_count": len(events),
        "historical": until_seq is not None,
        "view": stream.view(until=until_seq),
    }


def event_delta(challenge_root: str, *, after_seq: int = 0, limit: int = 500) -> dict[str, Any]:
    """Return ordered STATE events after ``after_seq`` with a bounded count."""
    if not isinstance(after_seq, int) or after_seq < 0:
        raise ValueError("after_seq must be a non-negative integer")
    if not isinstance(limit, int) or limit < 1 or limit > 5000:
        raise ValueError("limit must be between 1 and 5000")
    events = Stream(os.path.abspath(challenge_root)).read()
    remaining = [event for event in events if event["seq"] > after_seq]
    selected = remaining[:limit]
    stream_id = events[0]["stream_id"] if events else None
    latest_seq = selected[-1]["seq"] if selected else after_seq
    return {
        "schema": EVENTS_SCHEMA,
        "stream_id": stream_id,
        "after_seq": after_seq,
        "events": selected,
        "cursor": {"stream_id": stream_id, "seq": latest_seq},
        "has_more": len(remaining) > len(selected),
    }


def telemetry(challenge_root: str) -> dict[str, Any]:
    events = Stream(os.path.abspath(challenge_root)).read()
    types = Counter(event["type"] for event in events)
    groups = Counter(event["type"].split(".", 1)[0] for event in events)
    return {
        "schema": TELEMETRY_SCHEMA,
        "event_count": len(events),
        "event_types": dict(sorted(types.items())),
        "groups": dict(sorted(groups.items())),
        "first_at": events[0]["at"] if events else None,
        "last_at": events[-1]["at"] if events else None,
    }


def list_artifacts(challenge_root: str, *, limit: int = 500) -> dict[str, Any]:
    if not isinstance(limit, int) or limit < 1 or limit > MAX_ARTIFACTS:
        raise ValueError("artifact limit must be between 1 and %d" % MAX_ARTIFACTS)
    store = Stream(os.path.abspath(challenge_root)).root
    meta_root = os.path.join(store, "metadata", "sha256")
    records: list[dict[str, Any]] = []
    if os.path.isdir(meta_root):
        for prefix in sorted(os.listdir(meta_root)):
            directory = os.path.join(meta_root, prefix)
            if not os.path.isdir(directory):
                continue
            for name in sorted(os.listdir(directory)):
                if not name.endswith(".json"):
                    continue
                digest = "sha256:" + prefix + name[:-5]
                try:
                    records.append(artifact_metadata(digest, root=store))
                except (OSError, ValueError, RuntimeError):
                    continue
    records.sort(key=lambda item: (str(item.get("created_at", "")), str(item.get("digest", ""))), reverse=True)
    selected = records[:limit]
    return {
        "schema": ARTIFACTS_SCHEMA,
        "artifacts": selected,
        "total": len(records),
        "has_more": len(records) > len(selected),
    }


def artifact_preview(challenge_root: str, digest: str, *, max_bytes: int = 65536) -> dict[str, Any]:
    if not isinstance(max_bytes, int) or max_bytes < 1 or max_bytes > MAX_PREVIEW:
        raise ValueError("max_bytes must be between 1 and %d" % MAX_PREVIEW)
    store = Stream(os.path.abspath(challenge_root)).root
    meta = artifact_metadata(digest, root=store)
    data = artifact_get(digest, root=store)
    chunk = data[:max_bytes]
    media = str(meta.get("media_type", "application/octet-stream"))
    textual = media.startswith("text/") or "json" in media or "xml" in media or "javascript" in media
    if textual:
        content, encoding = chunk.decode("utf-8", "replace"), "utf-8"
    else:
        content, encoding = base64.b64encode(chunk).decode("ascii"), "base64"
    return {
        "schema": PREVIEW_SCHEMA,
        "metadata": meta,
        "encoding": encoding,
        "content": content,
        "truncated": len(data) > len(chunk),
        "preview_bytes": len(chunk),
        "total_bytes": len(data),
    }
