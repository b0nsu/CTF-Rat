#!/usr/bin/env python3
"""Executable P2 category gate; fixtures build a local native toy binary."""
import argparse, pathlib, subprocess, sys
p=argparse.ArgumentParser(); p.add_argument("--category",choices=("core","heap","rop","runtime","vm"),required=True); a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
# The fixture tests intentionally exercise all extension contracts; categories
# remain separate CLI gates so CI can shard them once dedicated corpus samples grow.
r=subprocess.run([sys.executable,"-m","unittest","tests.test_p2_analysis"],cwd=root)
print("analysis %s: %s"%(a.category,"PASS" if r.returncode==0 else "FAIL"))
raise SystemExit(r.returncode)
