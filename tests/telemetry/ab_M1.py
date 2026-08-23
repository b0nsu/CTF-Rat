#!/usr/bin/env python3
"""M1-5: context-load A/B between the old forced-doctrine entrypoint and the
M1 slim FAST hot-path. Read-only; no binary execution, no network.

Baseline (pre-M1, commit ab22a6a) forced CLAUDE.md's "읽는 순서" to pull in
doctrine/SOLVING.md -> SOLVABILITY.md -> PRIMITIVE_GATE.md ->
knowledge/GROUNDING_INDEX.md on every FAST session. M1 makes those DEEP-only;
the slim CLAUDE.md alone is now the FAST session's forced context.

Token counts are a documented heuristic (chars // 4), not a real tokenizer --
good enough for a relative before/after comparison, not for absolute budgets.
"""
from __future__ import annotations
import json, os, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OLD_REF = "ab22a6a"  # main tip immediately before feat/m1-slim-entrypoint diverged

def estimate_tokens(text):
    return max(1, len(text) // 4)

def git_show(ref, path):
    out = subprocess.run(["git", "show", "%s:%s" % (ref, path)], cwd=ROOT,
                          capture_output=True, text=True, check=True)
    return out.stdout

def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()

OLD_FAST_FILES = [
    "CLAUDE.md",
    "doctrine/SOLVING.md",
    "doctrine/SOLVABILITY.md",
    "doctrine/PRIMITIVE_GATE.md",
    "knowledge/GROUNDING_INDEX.md",
]
NEW_FAST_FILES = ["CLAUDE.md"]

def main():
    old_texts = {p: git_show(OLD_REF, p) for p in OLD_FAST_FILES}
    new_texts = {p: read(p) for p in NEW_FAST_FILES}

    old_tokens = {p: estimate_tokens(t) for p, t in old_texts.items()}
    new_tokens = {p: estimate_tokens(t) for p, t in new_texts.items()}
    old_total = sum(old_tokens.values())
    new_total = sum(new_tokens.values())

    row = {
        "schema": "rat.session-metrics/v1",
        "ab": "M1-slim-entrypoint",
        "baseline_ref": OLD_REF,
        "old_forced_files": OLD_FAST_FILES,
        "old_forced_doctrine_loads": len(OLD_FAST_FILES) - 1,
        "new_forced_files": NEW_FAST_FILES,
        "new_forced_doctrine_loads": 0,
        "old_context_tokens_est": old_total,
        "new_context_tokens_est": new_total,
        "context_reduction_pct": round(100 * (1 - new_total / old_total), 1),
        "per_file_tokens_est": {"old": old_tokens, "new": new_tokens},
        "token_estimator": "len(text)//4 (heuristic, not a real tokenizer)",
    }

    out_path = os.path.join(os.path.dirname(__file__), "ab_M1.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(row, indent=2, ensure_ascii=False))
    print("wrote", out_path)

if __name__ == "__main__":
    main()
