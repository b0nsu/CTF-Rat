"""Deterministic, bounded projection of STATE v2 for agent context.

The state stream remains the source of truth.  This module only renders a
small read-only projection suitable for an LLM context window; it never
promotes findings, mutates evidence, or changes verification semantics.
"""
from __future__ import annotations

import json
from typing import Any

SECTION_ORDER = ("FACTS", "PRIMITIVES", "NEXT", "RULED OUT", "UNKNOWNS", "HYPOTHESES")


def _short(value: Any, limit: int = 220) -> str:
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            text = repr(value)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _finding_text(finding_id: str, finding: dict[str, Any]) -> str:
    title = finding.get("title") or finding.get("text") or finding_id
    confidence = finding.get("confidence")
    suffix = ""
    if isinstance(confidence, (int, float)):
        suffix = f" confidence={confidence:.2f}"
    return f"[{finding.get('state', 'unknown').upper()}] {finding_id}: {_short(title)}{suffix}"


def _observation_text(observation_id: str, observation: dict[str, Any]) -> str:
    quality = observation.get("quality", {}).get("level", "unknown")
    kind = observation.get("kind", "observation")
    return f"[{quality.upper()}] {observation_id} {kind}: {_short(observation.get('value'))}"


def _primitive_text(primitive_id: str, primitive: dict[str, Any]) -> str:
    status = primitive.get("status", "unknown").upper()
    kind = primitive.get("kind") or primitive.get("name") or primitive_id
    return f"[{status}] {primitive_id}: {_short(kind)}"


def _payload_text(identifier: str, payload: dict[str, Any]) -> str:
    return f"{identifier}: {_short(payload.get('text') or payload.get('probe') or payload)}"


def candidates(view: dict[str, Any]) -> list[dict[str, Any]]:
    """Return deterministic candidate lines with lower numeric priority first."""
    out: list[dict[str, Any]] = []

    for finding_id, finding in sorted(view.get("findings", {}).items()):
        state = finding.get("state", "unknown")
        priority = {
            "verified": 5,
            "confirmed": 8,
            "supported": 18,
            "proposed": 55,
            "stale": 80,
            "invalidated": 90,
            "refuted": 95,
        }.get(state, 70)
        section = "RULED OUT" if state in {"refuted", "invalidated"} else "FACTS"
        out.append({"section": section, "priority": priority, "id": finding_id, "text": _finding_text(finding_id, finding)})

    for primitive_id, primitive in sorted(view.get("primitives", {}).items()):
        status = primitive.get("status", "unknown")
        priority = {"consumed": 6, "pass": 10, "candidate": 38, "blocked": 50, "fail": 65, "stale": 75}.get(status, 70)
        out.append({"section": "PRIMITIVES", "priority": priority, "id": primitive_id, "text": _primitive_text(primitive_id, primitive)})

    for idx, probe in enumerate(view.get("next_probes", [])):
        ident = str(probe.get("probe") or f"probe-{idx + 1}")
        out.append({"section": "NEXT", "priority": 15 + idx, "id": ident, "text": _payload_text(ident, probe)})

    for fingerprint, payload in sorted(view.get("ruled_out", {}).items()):
        out.append({"section": "RULED OUT", "priority": 28, "id": fingerprint, "text": _payload_text(fingerprint, payload)})

    for unknown_id, payload in sorted(view.get("unknowns", {}).items()):
        out.append({"section": "UNKNOWNS", "priority": 32, "id": unknown_id, "text": _payload_text(unknown_id, payload)})

    for hypothesis_id, payload in sorted(view.get("hypotheses", {}).items()):
        out.append({"section": "HYPOTHESES", "priority": 42, "id": hypothesis_id, "text": _payload_text(hypothesis_id, payload)})

    # Direct active observations are facts, but rank below explicit findings so
    # an observation-heavy stream cannot crowd out the actual conclusions.
    for observation_id, observation in sorted(view.get("observations", {}).items()):
        if observation.get("validity", {}).get("state") != "active":
            continue
        quality = observation.get("quality", {}).get("level")
        priority = {"direct": 24, "derived": 48, "heuristic": 68}.get(quality, 68)
        out.append({"section": "FACTS", "priority": priority, "id": observation_id, "text": _observation_text(observation_id, observation)})

    return sorted(out, key=lambda item: (item["priority"], SECTION_ORDER.index(item["section"]), item["id"]))


def _render(selected: list[dict[str, Any]], omitted: int = 0) -> str:
    by_section = {name: [] for name in SECTION_ORDER}
    for item in selected:
        by_section[item["section"]].append(item["text"])
    lines = ["== STATE SNAPSHOT =="]
    for section in SECTION_ORDER:
        if not by_section[section]:
            continue
        lines.append(section + ":")
        lines.extend("  " + text for text in by_section[section])
    if len(lines) == 1:
        lines.append("(no active state)")
    if omitted:
        lines.append(f"... {omitted} lower-priority state item(s) omitted by budget")
    return "\n".join(lines)


def snapshot(view: dict[str, Any], *, budget_tokens: int = 1200, max_bytes: int | None = None) -> dict[str, Any]:
    """Build a bounded snapshot.

    ``budget_tokens`` is intentionally an approximation (4 UTF-8 bytes/token)
    because this command must remain model-agnostic.  ``max_bytes`` can impose
    a stricter deterministic wire-size ceiling.
    """
    if not isinstance(budget_tokens, int) or budget_tokens <= 0:
        raise ValueError("budget_tokens must be a positive integer")
    limit = budget_tokens * 4
    if max_bytes is not None:
        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("max_bytes must be a positive integer")
        limit = min(limit, max_bytes)
    if limit < 64:
        raise ValueError("context budget is too small")

    pool = candidates(view)
    selected: list[dict[str, Any]] = []
    for item in pool:
        trial = selected + [item]
        if len(_render(trial).encode("utf-8")) <= limit:
            selected = trial

    omitted = len(pool) - len(selected)
    text = _render(selected, omitted)
    # The omission footer itself can push the output over budget. Remove the
    # least-important selected items until the final rendered projection fits.
    while len(text.encode("utf-8")) > limit and selected:
        selected.pop()
        omitted += 1
        text = _render(selected, omitted)
    if len(text.encode("utf-8")) > limit:
        text = _render([], 0)
        if len(text.encode("utf-8")) > limit:
            text = "STATE SNAPSHOT"

    return {
        "schema": "rat.context-snapshot/v1",
        "budget_tokens": budget_tokens,
        "max_bytes": limit,
        "used_bytes": len(text.encode("utf-8")),
        "selected": selected,
        "omitted": omitted,
        "text": text,
    }
