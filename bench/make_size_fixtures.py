#!/usr/bin/env python3
"""Generate fixed-size ELF fixtures and a manifest for large-binary baselines.

Sizes are chosen around the 2MiB angr soft limit so both sides of the boundary
are measured with identical code:

    small           the compiled fixture as-is (unstripped)
    small-stripped  the same binary after strip
    1mib            zero-padded to 1 MiB
    2mib-under      2 MiB - 1  (guard allows)
    2mib-at         2 MiB      (guard allows; size <= limit)
    2mib-over       2 MiB + 1  (guard refuses)
    2mib-over-stripped  the 2MiB+1 padded binary stripped (no symbols)
    4mib            4 MiB
    semantic        a small checker with both success/failure oracle strings
    semantic-stripped  the same checker stripped

Zero bytes appended after the last section keep the ELF valid; loaders ignore
trailing data. Outputs go to bench/fixtures/large-size/, whose caches are
globally ignored (*.revq.json). Regenerate rather than committing binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# Same recipe ratbench uses so fixture builds match benchmark builds.
COMPILE_CMD = ["gcc", "-w", "-O0", "-fno-stack-protector", "-no-pie"]
DEFAULT_SOURCE = REPO / "bench" / "artifacts" / "stack-basic-01" / "src.c"
SEMANTIC_SOURCE = REPO / "bench" / "large_binary_semantic.c"
DEFAULT_OUT = REPO / "bench" / "fixtures" / "large-size"

# name -> target total size in bytes (None = leave the compiled size)
TARGETS = {
    "small": None,
    "small-stripped": None,
    "1mib": 1 * 1024 * 1024,
    "2mib-under": 2 * 1024 * 1024 - 1,
    "2mib-at": 2 * 1024 * 1024,
    "2mib-over": 2 * 1024 * 1024 + 1,
    "2mib-over-stripped": 2 * 1024 * 1024 + 1,
    "4mib": 4 * 1024 * 1024,
    "semantic": None,
    "semantic-stripped": None,
}
STRIPPED = {"small-stripped", "2mib-over-stripped", "semantic-stripped"}


def run(cmd, timeout, what) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        sys.exit("%s timed out after %ss" % (what, timeout))
    if proc.returncode != 0:
        sys.exit("%s failed (%d): %s" % (what, proc.returncode, proc.stderr.strip()))
    return proc


def pad_to(src: Path, dst: Path, total: int) -> None:
    data = src.read_bytes()
    if len(data) > total:
        raise ValueError("source ELF (%d bytes) already exceeds target %d" % (len(data), total))
    dst.write_bytes(data + b"\x00" * (total - len(data)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                        help="fixture C source (default: stack-basic-01)")
    parser.add_argument("--outdir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    if not args.source.is_file():
        sys.exit("missing source: %s" % args.source)
    args.outdir.mkdir(parents=True, exist_ok=True)

    gcc_version = subprocess.run(["gcc", "--version"], capture_output=True,
                                 text=True).stdout.splitlines()[0]
    base = args.outdir / "_base"
    run(COMPILE_CMD + [str(args.source), "-o", str(base)], 60, "gcc")
    semantic_base = args.outdir / "_semantic_base"
    run(COMPILE_CMD + [str(SEMANTIC_SOURCE), "-o", str(semantic_base)], 60, "gcc")

    manifest = {
        "schema": "rat.large-binary-fixtures/v1",
        "generated_at_epoch": time.time(),
        "source": str(args.source.relative_to(REPO)) if args.source.is_relative_to(REPO) else str(args.source),
        "compile_command": COMPILE_CMD,
        "gcc": gcc_version,
        "host": {"platform": platform.platform(), "python": sys.version.split()[0],
                 "cpu_count": os.cpu_count()},
        "note": ("the 2MiB limit is revq DEFAULT_MAX_ANGR_INPUT_MB / analysis.py "
                 "ANGR_SOFT_LIMIT_BYTES; sizes exercise both sides of that boundary"),
        "fixtures": [],
    }
    strip = shutil.which("strip")
    for name, total in TARGETS.items():
        out = args.outdir / name
        source = SEMANTIC_SOURCE if name.startswith("semantic") else args.source
        shutil.copyfile(semantic_base if name.startswith("semantic") else base, out)
        if name in STRIPPED:
            # Strip before padding: strip rewrites the ELF and would drop
            # the trailing zero block otherwise.
            if not strip:
                sys.exit("strip not available")
            run([strip, str(out)], 30, "strip")
        if total is not None:
            pad_to(out, out, total)
        data = out.read_bytes()
        opts = {
            "name": name,
            "path": str(out.relative_to(REPO)),
            "source": str(source.relative_to(REPO)),
            "size_bytes": len(data),
            "stripped": name in STRIPPED,
            "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        }
        manifest["fixtures"].append(opts)
        print("%-20s %10d bytes  stripped=%s  %s" % (name, len(data), opts["stripped"], opts["sha256"][:44]))

    base.unlink()
    semantic_base.unlink()
    manifest_path = args.outdir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print("manifest: %s" % manifest_path.relative_to(REPO))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
