#!/usr/bin/env python3
"""Reproduce revq cold/warm and size-boundary measurements on local fixtures.

The padded fixtures test file-size guard behavior, not CFG cost scaling: their
executable code is identical to `small`. The semantic fixture checks xrefs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from profile_large_binary import run

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "bench" / "fixtures" / "large-size"
CASES = [
    ("small", False), ("small-stripped", False), ("semantic", False),
    ("semantic-stripped", False), ("1mib", False),
    ("2mib-under", False), ("2mib-at", False),
    ("2mib-over", False), ("2mib-over", True),
    ("2mib-over-stripped", True), ("4mib", False), ("4mib", True),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    parser.add_argument("--output", type=Path, default=REPO / "bench" / "results" / "large-binary-matrix.json")
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    manifest = json.loads((args.fixtures / "manifest.json").read_text())
    entries = {item["name"]: item for item in manifest["fixtures"]}
    rows = []
    for name, explicit in CASES:
        binary = args.fixtures / name
        if name not in entries or not binary.is_file():
            parser.error("missing fixture %s; run make_size_fixtures.py" % name)
        for cache in ("cold", "warm"):
            # Refusal never creates a revq cache, so a "warm" run would be a
            # duplicate cold refusal with a misleading condition label.
            if cache == "warm" and name in {"2mib-over", "4mib"} and not explicit:
                continue
            command = [str(REPO / "bin" / "revq"), "{binary}", "--format", "json"]
            if cache == "cold":
                command.append("--refresh")
            if explicit:
                command.append("--allow-large")
            result = run(binary, command, args.timeout, cache, "revq-v6")
            if result["input"]["sha256"] != entries[name]["sha256"]:
                parser.error("fixture digest changed: %s" % name)
            rows.append({"fixture": name, "explicit_large": explicit, "profile": result})
            print("%-20s %-5s explicit=%s exit=%s wall=%ss RSS=%s KiB" %
                  (name, cache, explicit, result["exit_code"], result["wall_seconds"],
                   result["sampled_peak_process_tree_rss_kib"]))
    output = {"schema": "rat.large-binary-matrix/v1", "fixture_manifest": str(args.fixtures / "manifest.json"),
              "note": "cold/warm refer to revq cache only; OS page cache was not controlled; zero padding does not increase code size",
              "rows": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
