#!/usr/bin/env python3
"""Measure independent CFGFast option changes against a revq semantic baseline.

Examples:
  python3 bench/cfgfast_options.py --binary bench/fixtures/large-size/small \
    --baseline bench/baselines/large-binary-small.json \
    --output bench/results/cfgfast-small.json

The worker does not read or write revq caches. Each variant runs in a separate
process, and the parent records time, peak group RSS, timeout and semantic loss.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

from profile_large_binary import run
from revq_semantics import _revq_module, compare, project

REPO = Path(__file__).resolve().parents[1]
VARIANTS = {
    "current": {"cross_references": True, "normalize": True},
    "no-cross-references": {"cross_references": False, "normalize": True},
    "no-normalize": {"cross_references": True, "normalize": False},
}


def worker(binary: Path, variant: str, output: Path) -> int:
    revq = _revq_module()
    rev = revq.extract_angr(str(binary), cfg_options=VARIANTS[variant],
                            string_ref_probe=True)
    rev["sha256"] = revq.sha256(str(binary))
    output.write_text(json.dumps(project(rev), ensure_ascii=False, sort_keys=True) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--cache", choices=("cold", "warm", "unknown"), default="cold")
    parser.add_argument("--worker", choices=tuple(VARIANTS), help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        if args.worker_output is None:
            parser.error("--worker-output required")
        return worker(args.binary, args.worker, args.worker_output)
    if not args.binary.is_file() or args.timeout <= 0:
        parser.error("--binary must be a file and --timeout must be positive")
    baseline = json.loads(args.baseline.read_text())
    if baseline.get("schema") != "rat.revq-semantics/v1":
        parser.error("baseline has wrong schema")
    import hashlib
    actual = "sha256:" + hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if baseline.get("input_sha256") != actual:
        parser.error("baseline input digest differs from --binary")
    rows = []
    with tempfile.TemporaryDirectory(prefix="rat-cfg-options-") as td:
        for name in VARIANTS:
            candidate_path = Path(td) / (name + ".json")
            angr_python = REPO / ".venv-angr" / "bin" / "python"
            command = [str(angr_python if angr_python.is_file() else Path(sys.executable)),
                       str(Path(__file__).resolve()),
                       "--binary", "{binary}", "--baseline", str(args.baseline.resolve()),
                       "--output", str(args.output.resolve()), "--worker", name,
                       "--worker-output", str(candidate_path)]
            profile = run(args.binary.resolve(), command, args.timeout, args.cache, None)
            comparison = None
            if profile["exit_code"] == 0 and candidate_path.is_file():
                comparison = compare(baseline, json.loads(candidate_path.read_text()))
            rows.append({"variant": name, "cfgfast_options": VARIANTS[name],
                         "profile": profile, "semantic_comparison": comparison})
    result = {"schema": "rat.cfgfast-option-experiment/v1", "baseline": str(args.baseline),
              "input_sha256": actual, "variants": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    for row in rows:
        diff = row["semantic_comparison"]
        loss = len(diff["xrefs"]["lost"]) if diff else "unknown"
        print("%-20s %7ss %8s KiB  lost xrefs=%s  exit=%s" %
              (row["variant"], row["profile"]["wall_seconds"],
               row["profile"]["sampled_peak_process_tree_rss_kib"],
               loss, row["profile"]["exit_code"]))
    return 0 if all(row["semantic_comparison"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
