"""Deterministic read projection of CTF-Rat state and artifacts for Desktop.

STATE v2 and the existing content-addressed artifact store remain canonical.
This module adds bounded projections only; it never creates a second database.
"""
from __future__ import annotations
import base64, json, os
from collections import Counter
from typing import Any

from .artifact import metadata as artifact_metadata, preview as artifact_read_preview
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


def _stream_stat(stream: Stream) -> tuple[int, int]:
    """Return the local size/mtime tuple used only as a change hint."""
    try:
        stat = os.stat(stream.path)
        return stat.st_size, stat.st_mtime_ns
    except OSError:
        return 0, 0


def _generation(stat: tuple[int, int]) -> str:
    """Encode file stat values as an opaque JS-safe string.

    ``st_mtime_ns`` commonly exceeds JavaScript's safe integer range. Keeping
    the generation opaque avoids precision loss when a Tauri/JS client echoes
    it back. This is only a performance hint, never canonical STATE evidence.
    """
    return "%d:%d" % stat


def _stream_tail_summary(stream: Stream) -> tuple[dict[str, Any], int]:
    """Summarize a stream already validated by ``Stream.view()``.

    This does not materialize STATE semantics. It only counts complete JSONL
    records and decodes the final complete event for its canonical cursor. A
    crash-truncated final record is ignored exactly as ``Stream.read()`` does.
    Callers must compare stream stat before/after the validating view + summary.
    """
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


def snapshot(challenge_root: str, *, until_seq: int | None = None) -> dict[str, Any]:
    """Return a materialized view, optionally at a historical event sequence."""
    root = os.path.abspath(challenge_root)
    stream = Stream(root)
    if until_seq is not None and (not isinstance(until_seq, int) or until_seq < 0):
        raise ValueError("until_seq must be a non-negative integer")

    if until_seq is None:
        # Live refresh is latency-sensitive. Stream.view() is the canonical
        # materializer and already performs one strict Stream.read(). Reuse that
        # validation and derive only cursor/count from raw JSONL bytes, avoiding
        # the previous second full JSON parse. Retry if a writer races the read.
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

    # Historical replay is interactive rather than a 500 ms polling path, and
    # this fallback also preserves correctness if a live stream changes during
    # all retry attempts.
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
    """Return ordered STATE events after ``after_seq`` with a bounded count.

    ``known_generation`` is an optional opaque client-echoed hint from a
    previous stable response. If it still matches, the append-only stream is
    unchanged and the expensive JSONL re-parse can be skipped. Any mismatch
    falls back to canonical ``Stream.read()`` validation.
    """
    if not isinstance(after_seq, int) or after_seq < 0:
        raise ValueError("after_seq must be a non-negative integer")
    if not isinstance(limit, int) or limit < 1 or limit > 5000:
        raise ValueError("limit must be between 1 and 5000")
    if stream_id is not None and (not isinstance(stream_id, str) or not stream_id):
        raise ValueError("stream_id must be a non-empty string")
    if known_generation is not None and (not isinstance(known_generation, str) or not known_generation):
        raise ValueError("known_generation must be a non-empty string")

    stream = Stream(os.path.abspath(challenge_root))
    before_stat = _stream_stat(stream)
    before_generation = _generation(before_stat)
    if known_generation is not None and known_generation == before_generation:
        return {
            "schema": EVENTS_SCHEMA,
            "stream_id": stream_id,
            "after_seq": after_seq,
            "events": [],
            "cursor": {
                "stream_id": stream_id,
                "seq": after_seq,
                "source_generation": before_generation,
            },
            "has_more": False,
            "reset": False,
            "unchanged": True,
        }

    # Only advertise a generation hint if the file remained stable around the
    # validated read. If a writer races us, omit the hint so the next request
    # must validate again rather than accidentally treating unread bytes as seen.
    stable = False
    events: list[dict[str, Any]] = []
    final_stat = before_stat
    for _ in range(3):
        read_stat = _stream_stat(stream)
        events = stream.read()
        final_stat = _stream_stat(stream)
        if read_stat == final_stat:
            stable = True
            break

    actual_stream_id = events[0]["stream_id"] if events else None
    reset = stream_id is not None and stream_id != actual_stream_id
    effective_after = 0 if reset else after_seq
    remaining = [event for event in events if event["seq"] > effective_after]
    selected = remaining[:limit]
    latest_seq = selected[-1]["seq"] if selected else effective_after
    cursor_doc: dict[str, Any] = {"stream_id": actual_stream_id, "seq": latest_seq}
    if stable:
        cursor_doc["source_generation"] = _generation(final_stat)
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
