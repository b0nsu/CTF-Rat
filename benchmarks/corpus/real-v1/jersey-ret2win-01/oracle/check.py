#!/usr/bin/env python3
"""Evaluator-only oracle: reads a candidate payload and injects a private flag."""
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
payload = sys.stdin.buffer.read()
with tempfile.TemporaryDirectory() as raw:
    work = pathlib.Path(raw)
    shutil.copy2(ROOT / "bin/challenge", work / "challenge")
    (work / "flag").write_text("REAL_V1_PRIVATE_ORACLE_TOKEN\n")
    run = subprocess.run([str(work / "challenge")], cwd=work, input=payload,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
    ok = b"control-flow-confirmed" in run.stdout and b"REAL_V1_PRIVATE_ORACLE_TOKEN" in run.stdout
sys.exit(0 if ok else 1)
