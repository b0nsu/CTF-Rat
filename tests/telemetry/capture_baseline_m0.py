#!/usr/bin/env python3
"""M0-3: cold-run rev fixtures through revq via contracts.execute() and capture
rat-metrics session metrics into tests/telemetry/baseline_M0.jsonl.

Read-only w.r.t. the repo; writes only under a temp dir and the output jsonl.
Intended to run inside docker/dev (needs angr for a full revq pass).
"""
from __future__ import annotations
import json, os, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))
from ratlib.contracts import execute
from ratlib.metrics import aggregate

FIXTURES = {
    "crackme_memcmp": r'''
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){char b[16]={0};if(read(0,b,11)<0)return 1;
if(memcmp(b,"s3cr3t_p4ss",11)==0)puts("Correct");else puts("Wrong");return 0;}
''',
    "crackme_strcmp": r'''
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){char b[32]={0};if(read(0,b,20)<0)return 1;
if(strcmp(b,"open_sesame_1234")==0)puts("Correct");else puts("Wrong");return 0;}
''',
    "crackme_xor": r'''
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){char b[16]={0};if(read(0,b,8)<0)return 1;
for(int i=0;i<8;i++)b[i]^=0x2a;
if(memcmp(b,"HELLOCTF",8)==0)puts("Correct");else puts("Wrong");return 0;}
''',
}

def build(src_path, bin_path):
    subprocess.run(["gcc", "-O1", "-s", src_path, "-o", bin_path], check=True)

def _pass(revq, binp, rat_root):
    return [
        execute([revq, binp, "--json"], root=rat_root, input_paths=(binp,), parameters={"mode": "json"}, timeout=60),
        execute([revq, binp, "--interesting"], root=rat_root, input_paths=(binp,), parameters={"mode": "interesting"}, timeout=60),
    ]

def run_fixture(name, source):
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, name + ".c")
        binp = os.path.join(td, name)
        with open(src, "w") as f:
            f.write(source)
        build(src, binp)
        rat_root = os.path.join(td, ".rat")
        revq = os.path.join(ROOT, "bin", "revq")
        cold_docs = _pass(revq, binp, rat_root)
        warm_docs = _pass(revq, binp, rat_root)
        rows = []
        for label, docs in (("cold", cold_docs), ("warm", warm_docs)):
            m = aggregate(docs)
            m["fixture"] = name
            m["cold_warm"] = label
            rows.append(m)
        return rows

def main():
    out_path = os.path.join(os.path.dirname(__file__), "baseline_M0.jsonl")
    lines = []
    for name, source in FIXTURES.items():
        try:
            for row in run_fixture(name, source):
                lines.append(json.dumps(row, sort_keys=True, ensure_ascii=False))
        except Exception as e:
            lines.append(json.dumps({"fixture": name, "error": str(e), "schema": "rat.session-metrics/v1"}, sort_keys=True))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %d lines to %s" % (len(lines), out_path))

if __name__ == "__main__":
    main()
