"""Deterministic typed evasion/packing observations for revq and route.

The detector consumes only already-collected static observations (imports,
strings, file entropy, section names).  It does not perform I/O and does not
assign a challenge route.  Human-readable text is a compatibility rendering of
typed signals; callers must not parse that rendering back into semantics.
"""
from __future__ import annotations

import math
import re

SIGNAL_SCHEMA = "rat.evasion-signals/v1"
ENTROPY_THRESHOLD = 7.2
ANTI_DEBUG_IMPORTS = ("ptrace", "personality", "prctl", "mprotect")
ANTI_DEBUG_STR = re.compile(
    r"ptrace|tracerpid|/proc/self/status|ld_preload|anti.?debug|/proc/self/maps",
    re.I,
)


def entropy(data):
    """Return Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    n = len(data)
    value = 0.0
    for count in freq:
        if count:
            p = count / n
            value -= p * math.log2(p)
    return value


def classify(imports, strings, file_entropy, sections):
    """Return stable typed observations; no route decision is made here."""
    import_set = {str(name) for name in (imports or []) if name}
    out = []

    for name in ANTI_DEBUG_IMPORTS:
        if name in import_set:
            out.append({
                "kind": "anti-debug-import",
                "value": {"api": name},
                "quality": "fact",
            })

    joined = " ".join(str(value) for value in (strings or []) if value is not None)
    match = ANTI_DEBUG_STR.search(joined)
    if match:
        out.append({
            "kind": "anti-debug-string",
            "value": {"match": match.group(0).lower()},
            "quality": "heuristic",
        })

    if file_entropy is not None and file_entropy >= ENTROPY_THRESHOLD:
        out.append({
            "kind": "high-entropy",
            "value": {
                "entropy": round(float(file_entropy), 2),
                "threshold": ENTROPY_THRESHOLD,
            },
            "quality": "heuristic",
        })

    seen_sections = set()
    for section in sections or []:
        if not section:
            continue
        name = str(section)
        upper = name.upper()
        if (upper.startswith("UPX") or "PACKED" in upper) and name not in seen_sections:
            seen_sections.add(name)
            out.append({
                "kind": "packer-section",
                "value": {"section": name},
                "quality": "fact",
            })

    return out


def render_legacy(signals):
    """Render the pre-v1 `evasion: [str, ...]` compatibility surface."""
    out = []
    for signal in signals or []:
        if not isinstance(signal, dict):
            continue
        kind = signal.get("kind")
        value = signal.get("value") or {}
        if kind == "anti-debug-import" and value.get("api"):
            out.append("import %s" % value["api"])
        elif kind == "anti-debug-string" and value.get("match"):
            out.append("문자열 '%s'" % value["match"])
        elif kind == "high-entropy" and isinstance(value.get("entropy"), (int, float)):
            out.append("고엔트로피 %.2f/8 (packing/암호화 의심)" % value["entropy"])
        elif kind == "packer-section" and value.get("section"):
            out.append("패커 섹션 %s" % value["section"])
    return out


def has_current_contract(rev):
    """Return whether a revmap carries the current typed evasion contract."""
    return (
        isinstance(rev, dict)
        and rev.get("evasion_signal_schema") == SIGNAL_SCHEMA
        and isinstance(rev.get("evasion_signals"), list)
    )
