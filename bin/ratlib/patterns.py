"""Small, source-bound hypothesis aids for provisional Router v2 leads."""
from __future__ import annotations

import hashlib
import os


# Exact headings in repo-owned hot-path cards. No vendored examples or executable
# snippets are copied into query results.
PATTERNS = {
    "heap-lifetime": ("pwn-heap", "SIGNALS", "FIRST ACTION", "PIVOT",
                      "allocator calls exist", "no reachable stale pointer or reuse", "decomp allocator/menu callsites"),
    "format-string": ("pwn-format", "SIGNALS", "FIRST ACTION", "PIVOT",
                      "user input reaches a printf-family call", "format argument is a fixed literal", "decomp printf-family callsite"),
    "stack-overwrite": ("pwn-stack", "SIGNALS", "FIRST ACTION", "PIVOT",
                        "input reaches a bounded or unbounded copy", "no overwrite reaches a controlled target", "pwncrash after callsite inspection"),
    "checker": ("rev-checker", "SIGNALS", "FIRST ACTION", "PIVOT",
                "comparison or success/failure oracle is present", "candidate path does not control verification", "rat query func <checker>"),
    "vm": ("rev-vm", "SIGNALS", "FIRST ACTION", "PIVOT",
           "dispatch-loop hint is present", "no actual bytecode dispatch loop", "decomp candidate dispatch function"),
    "packing": ("rev-packed", "SIGNALS", "FIRST ACTION", "PIVOT",
                "packing or entropy signal is present", "static image already exposes original code", "gdbq bounded entry observation"),
}
KNOWLEDGE = {
    "heap-lifetime": ("knowledge/ctf-skills/heap-techniques.md", "Heap Exploitation"),
    "format-string": ("knowledge/ctf-skills/format-string.md", "Format String Basics"),
    "stack-overwrite": ("knowledge/ctf-skills/overflow-basics.md", "Stack Buffer Overflow"),
}


class SourceStaleError(ValueError):
    pass


def _section(source: str, heading: str) -> str:
    marker = "## " + heading
    lines = source.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == marker]
    if len(starts) != 1:
        raise ValueError("missing or ambiguous section: " + marker)
    end = next((i for i in range(starts[0] + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[starts[0] + 1:end]).strip()


def project_patterns(leads, signals, *, root: str, budget_bytes: int = 8192, max_cards: int = 3,
                     expected_digests=None):
    """Project exact source sections; deterministic order is lexical, not a rank."""
    if not isinstance(leads, list) or not all(isinstance(x, str) for x in leads):
        raise ValueError("leads must be a list of strings")
    if not isinstance(signals, list) or not all(isinstance(x, dict) for x in signals):
        raise ValueError("signals must be a list of objects")
    if budget_bytes < 1 or not 1 <= max_cards <= 3:
        raise ValueError("budget_bytes must be positive and max_cards must be 1..3")
    if expected_digests is None: expected_digests = {}
    if not isinstance(expected_digests, dict): raise ValueError("expected_digests must be a mapping")
    known_sources = {"skills/%s/SKILL.md" % row[0] for row in PATTERNS.values()}
    known_sources.update(path for path, _heading in KNOWLEDGE.values())
    if set(expected_digests) - known_sources:
        raise ValueError("expected source path is not in the pattern catalog")
    cards, diagnostics, used = [], [], 0
    matched_leads = sorted(set(leads) & PATTERNS.keys())
    for lead in matched_leads:
        skill, signal_heading, action_heading, pivot_heading, premise, refutation, experiment = PATTERNS[lead]
        rel = "skills/%s/SKILL.md" % skill
        path = os.path.join(root, rel)
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            actual_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if rel in expected_digests and expected_digests[rel] != actual_digest:
                raise SourceStaleError("source revision differs from expected digest")
            source = raw.decode("utf-8")
            excerpts = {heading.lower().replace(" ", "_"): _section(source, heading)
                        for heading in (signal_heading, action_heading, pivot_heading)}
        except (OSError, UnicodeError, ValueError) as exc:
            diagnostics.append({"code": "source_stale" if isinstance(exc, SourceStaleError) else "source_invalid",
                                "severity": "warning", "message": "%s: %s" % (rel, exc)})
            continue
        matching = sorted(s["kind"] for s in signals if isinstance(s.get("kind"), str)
                          and ((lead == "heap-lifetime" and s["kind"] == "heap-imports")
                               or (lead == "format-string" and s["kind"] == "format-input-imports")
                               or (lead == "stack-overwrite" and s["kind"] == "overflow-imports")
                               or (lead == "checker" and s["kind"] == "checker-function")
                               or (lead == "vm" and s["kind"] == "vm-dispatch-hint")
                               or (lead == "packing" and s["kind"] in {"packer-section", "high-entropy"})))
        card = {"id": lead, "kind": "hypothesis-aid", "source": {"path": rel,
                "sections": [signal_heading, action_heading, pivot_heading],
                "digest": actual_digest},
                "selection": {"lead": lead, "signals": matching, "rule": "exact Router v2 lead; lexical order"},
                "premise": premise, "refutation": refutation, "next_experiment": experiment,
                "excerpt": excerpts, "direct_evidence": False}
        if lead in KNOWLEDGE:
            knowledge_path, knowledge_heading = KNOWLEDGE[lead]
            try:
                with open(os.path.join(root, knowledge_path), "rb") as handle:
                    knowledge_raw = handle.read()
                knowledge_digest = "sha256:" + hashlib.sha256(knowledge_raw).hexdigest()
                if knowledge_path in expected_digests and expected_digests[knowledge_path] != knowledge_digest:
                    raise SourceStaleError("source revision differs from expected digest")
                section = _section(knowledge_raw.decode("utf-8"), knowledge_heading)
                # A short original paragraph is enough to link the candidate to
                # its corpus anchor; no full example or writeup is preloaded.
                excerpt = section.split("\n\n", 1)[0].strip()
                card["knowledge"] = {"path": knowledge_path, "section": knowledge_heading,
                                     "digest": knowledge_digest,
                                     "excerpt": excerpt[:300]}
            except (OSError, UnicodeError, ValueError) as exc:
                diagnostics.append({"code": "source_stale" if isinstance(exc, SourceStaleError) else "source_invalid",
                                    "severity": "warning",
                                    "message": "%s: %s" % (knowledge_path, exc)})
                continue
        import json
        size = len(json.dumps(card, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        if used + size > budget_bytes:
            diagnostics.append({"code": "budget_omitted", "severity": "warning", "message": "%s omitted: source and candidate exceed budget" % lead})
            continue
        cards.append(card); used += size
        if len(cards) >= max_cards:
            if any(other > lead for other in matched_leads):
                diagnostics.append({"code": "card_limit", "severity": "warning",
                                    "message": "additional matching leads omitted at max_cards=%d" % max_cards})
            break
    return cards, diagnostics
