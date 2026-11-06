#!/usr/bin/env python3
"""Generate code-dense ELF inputs for bounded CFGFast cost measurements.

Unlike make_size_fixtures.py's zero-padded guard cases, these files have many
real function symbols and basic blocks. Generated binaries remain local.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
COUNTS = {"dense-1mib": 4096, "dense-4mib": 16384}


def assembly(count: int) -> str:
    lines = [".text", ".globl main", ".type main,@function", "main:",
             "xorl %eax,%eax", "ret", ".size main,.-main"]
    for index in range(count):
        name = "dense_%05d" % index
        lines.extend([".globl " + name, ".type " + name + ",@function",
                      name + ":", "movl $%d, %%eax" % index,
                      ".rept 16", "addl $3,%eax", "testl $1,%eax",
                      "je 1f", "xorl $5,%eax", "1:", ".endr", "ret",
                      ".size " + name + ",.-" + name])
    lines.append('.section .note.GNU-stack,"",@progbits')
    return "\n".join(lines) + "\n"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return "sha256:" + h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, default=REPO / "bench" / "fixtures" / "large-size")
    args = parser.parse_args()
    args.outdir.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="rat-dense-build-") as directory:
        source = Path(directory) / "dense.s"
        for name, count in COUNTS.items():
            source_text = assembly(count)
            source.write_text(source_text)
            output = args.outdir / name
            command = ["gcc", "-no-pie", str(source), "-o", str(output)]
            subprocess.run(command, check=True, capture_output=True, timeout=120)
            row = {"name": name, "path": str(output), "functions": count + 1,
                   "size_bytes": output.stat().st_size, "sha256": digest(output),
                   "assembly_sha256": "sha256:" + hashlib.sha256(source_text.encode()).hexdigest(),
                   "compile_recipe": ["gcc", "-no-pie", "<generated-assembly>", "-o", name]}
            rows.append(row)
            print("%s: %d bytes, %d functions, %s" %
                  (name, row["size_bytes"], row["functions"], row["sha256"]))
    manifest = {"schema": "rat.dense-binary-fixtures/v1",
                "platform": platform.platform(), "generator_sha256": digest(Path(__file__)),
                "gcc": subprocess.run(["gcc", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
                "reproduce_command": "python3 bench/make_dense_fixtures.py",
                "fixtures": rows}
    (args.outdir / "dense_manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
