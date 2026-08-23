"""Deterministic read projection of CTF-Rat state and artifacts for Desktop.

STATE v2 and the existing content-addressed artifact store remain canonical.
This module adds bounded projections only; it never creates a second database.
"""
from __future__ import annotations
import base64, copy, json, os
from collections import Counter
from typing import Any

from .artifact import describe as artifact_describe, preview as artifact_read_preview
from .state_v2 import Stream, cursor

SNAPSHOT_SCHEMA = "rat.desktop.snapshot/v1"
EVENTS_SCHEMA = "rat.desktop.events/v1"
LIVE_SCHEMA = "rat.desktop.live/v1"
ARTIFACTS_SCHEMA = "rat.desktop.artifacts/v1"
PREVIEW_SCHEMA = "rat.desktop.artifact-preview/v1"
TELEMETRY_SCHEMA = "rat.desktop.telemetry/v1"
MAX_ARTIFACTS = 2000
MAX_PREVIEW = 256 * 1024


class _EventBackedStream(Stream):
    """Feed already-validated events through the canonical Stream.view().

    ``Stream.view`` mutates some projected payload dictionaries while applying
    invalidation/consumption state, so live_update supplies a deep copy. This
    adapter owns no state semantics; it only prevents a second JSONL parse while
    reusing the canonical materializer unchanged.
    """

    def __init__(self, challenge_root: str, events: list[dict[str, Any]]):
        super().__init__(challenge_root)
        self._validated_events = events

    def read(self):
        return self._validated_events


def _manifest(challenge_root: str) -> dict[str, Any] | None:
    path = os.path.join(os.path.abspath(challenge_root), "run.json")
    try:
        with open(path, encoding="utf-8") as source:
            doc = json.load(source)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def _stream_stat(stream: Stream) -> tuple[int, int]:
    """Return the local size/mtime tuple used only as a change hint."""
    try:
        stat = os.stat(stream.path)
        return stat.st_size, stat.st_mtime_ns
    except OSError:
        return 0, 0


def _generation(stat: tuple[int, int]) -> str:
    """Encode file stat values as an opaque JS-safe string."""
    return "%d:%d" % stat


def _stream_tail_summary(stream: Stream) -> tuple[dict[str, Any], int]:
    """Summarize a stream already validated by ``Stream.view()``."""
    try:
        with open(stream.path, "rb") as source:
            data = source.read()
    except OSError:
        return {"stream_id": None, "seq": 0}, 0
    if not data:
        return {"stream_id": None, "seq": 0}, 0
    if not data.endswith(b"\n"):
        boundary = data.rfind(b"\n")
        data = b"" if boundary < 0 else data[:boundary + 1]
    if not data:
        return {"stream_id": None, "seq": 0}, 0
    count = data.count(b"\n")
    last_line = data[:-1].rsplit(b"\n", 1)[-1]
    event = json.loads(last_line.decode("utf-8"))
    return cursor(event), count


def _validate_delta_request(after_seq: int, limit: int, stream_id: str | None, known_generation: str | None) -> None:
    if not isinstance(after_seq, int) or after_seq < 0:
        raise ValueError("after_seq must be a non-negative integer")
    if not isinstance(limit, int) or limit < 1 or limit > 5000:
        raise ValueError("limit must be between 1 and 5000")
    if stream_id is not None and (not isinstance(stream_id, str) or not stream_id):
        raise ValueError("stream_id must be a non-empty string")
    if known_generation is not None and (not isinstance(known_generation, str) or not known_generation):
        raise ValueError("known_generation must be a non-empty string")


def _delta_document(
    events: list[dict[str, Any]],
    *,
    after_seq: int,
    limit: int,
    stream_id: str | None,
    source_generation: str | None,
) -> dict[str, Any]:
    actual_stream_id = events[0]["stream_id"] if events else None
    reset = stream_id is not None and stream_id != actual_stream_id
    effective_after = 0 if reset else after_seq
    remaining = [event for event in events if event["seq"] > effective_after]
    selected = remaining[:limit]
    latest_seq = selected[-1]["seq"] if selected else effective_after
    cursor_doc: dict[str, Any] = {"stream_id": actual_stream_id, "seq": latest_seq}
    if source_generation is not None:
        cursor_doc["source_generation"] = source_generation
    return {
        "schema": EVENTS_SCHEMA,
        "stream_id": actual_stream_id,
        "after_seq": effective_after,
        "events": selected,
        "cursor": cursor_doc,
        "has_more": len(remaining) > len(selected),
        "reset": reset,
        "unchanged": False,
    }


def _unchanged_delta(after_seq: int, stream_id: str | None, generation: str) -> dict[str, Any]:
    return {
        "schema": EVENTS_SCHEMA,
        "stream_id": stream_id,
        "after_seq": after_seq,
        "events": [],
        "cursor": {
            "stream_id": stream_id,
            "seq": after_seq,
            "source_generation": generation,
        },
        "has_more": False,
        "reset": False,
        "unchanged": True,
    }


def _snapshot_from_events(challenge_root: str, events: list[dict[str, Any]], view: dict[str, Any]) -> dict[str, Any]:
    latest = cursor(events[-1]) if events else {"stream_id": None, "seq": 0}
    return {
        "schema": SNAPSHOT_SCHEMA,
        "challenge_root": os.path.abspath(challenge_root),
        "run": _manifest(challenge_root),
        "cursor": latest,
        "event_count": len(events),
        "total_event_count": len(events),
        "historical": False,
        "view": view,
    }


def snapshot(challenge_root: str, *, until_seq: int | None = None) -> dict[str, Any]:
    """Return a materialized view, optionally at a historical event sequence."""
    root = os.path.abspath(challenge_root)
    stream = Stream(root)
    if until_seq is not None and (not isinstance(until_seq, int) or until_seq < 0):
        raise ValueError("until_seq must be a non-negative integer")

    if until_seq is None:
        for _ in range(3):
            before_stat = _stream_stat(stream)
            view = stream.view()
            latest, count = _stream_tail_summary(stream)
            after_stat = _stream_stat(stream)
            if before_stat == after_stat:
                return {
                    "schema": SNAPSHOT_SCHEMA,
                    "challenge_root": root,
                    "run": _manifest(root),
                    "cursor": latest,
                    "event_count": count,
                    "total_event_count": count,
                    "historical": False,
                    "view": view,
                }

    events = stream.read()
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


def event_delta(
    challenge_root: str,
    *,
    after_seq: int = 0,
    limit: int = 500,
    stream_id: str | None = None,
    known_generation: str | None = None,
) -> dict[str, Any]:
    """Return ordered STATE events after ``after_seq`` with a bounded count."""
    _validate_delta_request(after_seq, limit, stream_id, known_generation)
    stream = Stream(os.path.abspath(challenge_root))
    before_generation = _generation(_stream_stat(stream))
    if known_generation is not None and known_generation == before_generation:
        return _unchanged_delta(after_seq, stream_id, before_generation)

    stable = False
    events: list[dict[str, Any]] = []
    final_stat = _stream_stat(stream)
    for _ in range(3):
        read_stat = _stream_stat(stream)
        events = stream.read()
        final_stat = _stream_stat(stream)
        if read_stat == final_stat:
            stable = True
            break
    return _delta_document(
        events,
        after_seq=after_seq,
        limit=limit,
        stream_id=stream_id,
        source_generation=_generation(final_stat) if stable else None,
    )


def live_update(
    challenge_root: str,
    *,
    after_seq: int = 0,
    limit: int = 500,
    stream_id: str | None = None,
    known_generation: str | None = None,
) -> dict[str, Any]:
    """Return delta + current snapshot from one validated STATE read on change.

    Unchanged polls preserve the generation fast path and return ``snapshot`` as
    ``None``. Changed polls parse/validate JSONL once, then reuse the canonical
    ``Stream.view`` materializer over a deep copy of those validated events.
    """
    _validate_delta_request(after_seq, limit, stream_id, known_generation)
    root = os.path.abspath(challenge_root)
    stream = Stream(root)
    before_generation = _generation(_stream_stat(stream))
    if known_generation is not None and known_generation == before_generation:
        return {
            "schema": LIVE_SCHEMA,
            "delta": _unchanged_delta(after_seq, stream_id, before_generation),
            "snapshot": None,
        }

    stable = False
    events: list[dict[str, Any]] = []
    final_stat = _stream_stat(stream)
    for _ in range(3):
        read_stat = _stream_stat(stream)
        events = stream.read()
        final_stat = _stream_stat(stream)
        if read_stat == final_stat:
            stable = True
            break
    source_generation = _generation(final_stat) if stable else None
    delta = _delta_document(
        events,
        after_seq=after_seq,
        limit=limit,
        stream_id=stream_id,
        source_generation=source_generation,
    )
    view_events = copy.deepcopy(events)
    view = _EventBackedStream(root, view_events).view()
    return {
        "schema": LIVE_SCHEMA,
        "delta": delta,
        "snapshot": _snapshot_from_events(root, events, view),
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
    """List artifact metadata without hashing every object in the store."""
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
                    records.append(artifact_describe(digest, root=store))
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
    meta, chunk, total = artifact_read_preview(digest, max_bytes=max_bytes, root=store)
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
        "truncated": total > len(chunk),
        "preview_bytes": len(chunk),
        "total_bytes": total,
    }
