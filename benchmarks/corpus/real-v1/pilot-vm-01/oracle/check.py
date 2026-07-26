#!/usr/bin/env python3
import pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
payload = b'F7DO'
with tempfile.TemporaryDirectory() as raw:
    work = pathlib.Path(raw)
    shutil.copy2(ROOT / "bin/challenge", work / "challenge")
    (work / "flag").write_text("REAL_V1_PRIVATE_ORACLE_TOKEN\n")
    run = subprocess.run([str(work / "challenge")], cwd=work, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
    ok = b"REAL_V1_PRIVATE_ORACLE_TOKEN" in run.stdout and b"confirmed" in run.stdout
sys.exit(0 if ok else 1)
