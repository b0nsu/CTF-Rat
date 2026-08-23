"""Read-only projection of CTF-Rat state for local desktop clients.

This module deliberately reuses STATE v2 as the canonical event/evidence source.
It does not create a second state database and it does not execute solver tools.
"""
from __future__ import annotations
import json, os
from typing import Any

from .state_v2 import Stream, cursor

SNAPSHOT_SCHEMA = "rat.desktop.snapshot/v1"
EVENTS_SCHEMA = "rat.desktop.events/v1"


def _manifest(challenge_root: str) -> dict[str, Any] | None:
    path = os.path.join(os.path.abspath(challenge_root), "run.json")
    try:
        with open(path, encoding="utf-8") as source:
            doc = json.load(source)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def snapshot(challenge_root: str) -> dict[str, Any]:
    """Return a deterministic materialized desktop view for one challenge."""
    root = os.path.abspath(challenge_root)
    stream = Stream(root)
    events = stream.read()
    latest = cursor(events[-1]) if events else {"stream_id": None, "seq": 0}
    return {
        "schema": SNAPSHOT_SCHEMA,
        "challenge_root": root,
        "run": _manifest(root),
        "cursor": latest,
        "event_count": len(events),
        "view": stream.view(),
    }


def event_delta(challenge_root: str, *, after_seq: int = 0, limit: int = 500) -> dict[str, Any]:
    """Return ordered events after ``after_seq`` with a bounded response size."""
    if not isinstance(after_seq, int) or after_seq < 0:
        raise ValueError("after_seq must be a non-negative integer")
    if not isinstance(limit, int) or limit < 1 or limit > 5000:
        raise ValueError("limit must be between 1 and 5000")
    root = os.path.abspath(challenge_root)
    events = Stream(root).read()
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
