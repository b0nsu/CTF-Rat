#!/usr/bin/env python3
"""Independent local oracle; never exposes its per-run token to a solver."""
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
candidate = sys.stdin.buffer.read()
with tempfile.TemporaryDirectory() as raw:
    work = pathlib.Path(raw)
    shutil.copy2(ROOT / "bin/fd", work / "fd")
    (work / "flag").write_text("P4_LOCAL_ORACLE_TOKEN\n")
    result = subprocess.run([str(work / "fd"), "4660"], cwd=work,
                            input=candidate, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=3)
    ok = result.returncode == 0 and b"good job :)" in result.stdout and b"P4_LOCAL_ORACLE_TOKEN" in result.stdout
sys.exit(0 if ok else 1)
