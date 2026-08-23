"""Deterministic success/failure oracle extraction from revq facts."""
from __future__ import annotations

import re
from typing import Any, Mapping

POSITIVE = re.compile(r"\b(?:correct|success|congrat(?:ulations)?|accepted|valid|granted|unlocked|nice|flag)\b", re.I)
NEGATIVE = re.compile(r"\b(?:wrong|incorrect|invalid|fail(?:ed|ure)?|denied|reject(?:ed)?|try\s+again)\b", re.I)


def classify(text: str) -> str | None:
    """Return success/failure only for unambiguous lexical oracle strings."""
    pos = bool(POSITIVE.search(text))
    neg = bool(NEGATIVE.search(text))
    if pos == neg:
        return None
    return "success" if pos else "failure"


def detect(rev: Mapping[str, Any], *, binary: str | None = None,
           cache: Mapping[str, Any] | None = None) -> dict[str, Any]:
    signals = []
    for rec in rev.get("strings", []):
        text = str(rec.get("val", ""))
        kind = classify(text)
        if not kind:
            continue
        xrefs = []
        for x in rec.get("xrefs", []):
            if not isinstance(x, Mapping):
                continue
            addr = x.get("addr")
            if not isinstance(addr, int) or addr <= 0:
                continue
            xrefs.append({"func": str(x.get("func", "?")), "addr": addr})
        signals.append({
            "kind": kind,
            "text": text[:160],
            "string_addr": rec.get("addr", 0),
            "xrefs": sorted(xrefs, key=lambda r: (r["addr"], r["func"]))[:16],
        })

    # revq xrefs identify the instruction that references a string. That is a
    # deterministic evidence locator, but it is not necessarily an angr basic
    # block entry address. Keep the addresses in the candidate document for
    # inspection/future CFG normalization, while generated symsolve commands
    # prefer lexical stdout targets so explore() cannot silently miss a
    # mid-block xref address and concrete verification remains enabled.
    find = sorted({x["addr"] for s in signals if s["kind"] == "success" for x in s["xrefs"]})
    avoid = sorted({x["addr"] for s in signals if s["kind"] == "failure" for x in s["xrefs"]})
    find_str = list(dict.fromkeys(s["text"] for s in signals if s["kind"] == "success"))
    avoid_str = list(dict.fromkeys(s["text"] for s in signals if s["kind"] == "failure"))

    ambiguity = []
    if not find_str:
        ambiguity.append("no unambiguous lexical success signal")
    if find_str and not find:
        ambiguity.append("success string has no xref locator; string oracle remains usable")
    if avoid_str and not avoid:
        ambiguity.append("failure string has no xref locator; string avoid remains usable")

    return {
        "schema": "rat.oracle-candidates/v1",
        "binary": binary or rev.get("bin"),
        "binary_sha256": rev.get("sha256"),
        "engine": rev.get("engine"),
        "analysis_complete": bool(rev.get("analysis_complete", False)),
        "signals": signals[:24],
        "targets": {
            "find": find[:8],
            "avoid": avoid[:8],
            "find_str": find_str[:4],
            "avoid_str": avoid_str[:4],
        },
        "ready": bool(find_str),
        "ambiguity": ambiguity,
        "cache": dict(cache or {}),
        "confidence": "candidate-only",
        "note": "xref addresses are evidence locators only; generated symsolve commands use lexical stdout targets until CFG block-entry normalization is proven",
    }


def symsolve_argv(doc: Mapping[str, Any], *, stdin: int | None = None,
                   arg: int | None = None, printable: bool = False,
                   charset: str | None = None, no_null: bool = False,
                   timeout: float | None = None) -> list[str]:
    if not doc.get("ready"):
        raise ValueError("oracle has no usable find target")
    binary = str(doc.get("binary") or "")
    if not binary:
        raise ValueError("oracle binary path missing")
    argv = [binary]
    targets = doc["targets"]

    # Prefer string conditions. Besides being safe for mid-block xrefs, this
    # keeps symsolve's concrete_verify path active. Address candidates remain
    # visible in the oracle document but are not promoted to control-flow facts.
    find_strs = list(targets.get("find_str", []))
    avoid_strs = list(targets.get("avoid_str", []))
    if find_strs:
        for text in find_strs:
            argv += ["--find-str", str(text)]
    else:
        for addr in targets.get("find", []):
            argv += ["--find", hex(int(addr))]
    if avoid_strs:
        for text in avoid_strs:
            argv += ["--avoid-str", str(text)]
    else:
        for addr in targets.get("avoid", []):
            argv += ["--avoid", hex(int(addr))]

    if stdin is not None:
        argv += ["--stdin", str(stdin)]
    if arg is not None:
        argv += ["--arg", str(arg)]
    if printable:
        argv.append("--printable")
    if charset:
        argv += ["--charset", charset]
    if no_null:
        argv.append("--no-null")
    if timeout is not None:
        argv += ["--timeout", str(timeout)]
    return argv


def shell_command(doc: Mapping[str, Any], **kwargs: Any) -> str:
    import shlex
    argv = symsolve_argv(doc, **kwargs)
    return "rat-adapt --root . --emit stdout symsolve " + " ".join(shlex.quote(x) for x in argv)


def render_text(doc: Mapping[str, Any]) -> str:
    lines = ["== ORACLE CANDIDATES =="]
    for signal in doc.get("signals", [])[:12]:
        anchors = ",".join(hex(x["addr"]) for x in signal.get("xrefs", [])[:4]) or "no-xref"
        lines.append("%s %-48r -> %s" % (signal["kind"].upper(), signal["text"], anchors))
    t = doc.get("targets", {})
    lines.append("FIND-STR   " + ("; ".join(repr(x) for x in t.get("find_str", [])) or "-"))
    lines.append("AVOID-STR  " + ("; ".join(repr(x) for x in t.get("avoid_str", [])) or "-"))
    if t.get("find") or t.get("avoid"):
        lines.append("XREF-LOC   find=%s avoid=%s" %
                     (", ".join(hex(x) for x in t.get("find", [])) or "-",
                      ", ".join(hex(x) for x in t.get("avoid", [])) or "-"))
    lines.append("READY      %s" % ("yes" if doc.get("ready") else "no"))
    if doc.get("ambiguity"):
        lines.append("CHECK      " + "; ".join(doc["ambiguity"]))
    return "\n".join(lines)
