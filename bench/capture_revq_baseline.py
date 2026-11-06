#!/usr/bin/env python3
"""Capture revq's current full-CFG semantics as a stable JSON reference.

Example:
  python3 bench/capture_revq_baseline.py --binary bench/fixtures/large-size/small \
    --output bench/baselines/large-binary-small.json

This runs revq with --refresh so a stale cache cannot silently become the
baseline. Resource telemetry belongs in profile_large_binary.py.
"""
from __future__ import annotations

import argparse
import json
import signal
from pathlib import Path
import subprocess
import sys
import tempfile

from profile_large_binary import _stop_tree
from revq_semantics import project

REPO = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args()
    if not args.binary.is_file() or args.timeout <= 0:
        parser.error("--binary must be a file and --timeout must be positive")
    command = [str(REPO / "bin" / "revq"), str(args.binary.resolve()),
               "--refresh", "--format", "json"]
    with tempfile.TemporaryFile(mode="w+t") as stdout, tempfile.TemporaryFile(mode="w+t") as stderr:
        proc = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                start_new_session=True, cwd=REPO)
        try:
            proc.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            _stop_tree(proc.pid, signal.SIGKILL)
            proc.wait()
            parser.exit(124, "revq baseline timed out after %ss\n" % args.timeout)
        if proc.returncode:
            stderr.seek(0, 2)
            stderr.seek(max(0, stderr.tell() - 2000))
            parser.exit(proc.returncode, "revq baseline failed: %s\n" % stderr.read())
        stdout.seek(0)
        result = project(json.load(stdout))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print("%s: %d functions, %d strings, %d xrefs" %
          (args.output, result["function_count"], len(result["strings"]),
           sum(len(s["xrefs"]) for s in result["strings"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
