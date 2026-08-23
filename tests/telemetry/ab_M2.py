#!/usr/bin/env python3
"""M2-5: measured A/B of rat-profile cache visibility before/after M2.

Calls rat-profile twice (cold, then warm on the identical binary) against
the OLD implementation and the NEW one, then compares via
ratlib.metrics.aggregate() over the resulting rat.tool-result/v1 envelopes.
rat-profile shells out to file/readelf/strings, so this must run where
subprocess execution works (docker/dev).

`git worktree add` over the virtiofs-mounted repo inside docker/dev hangs;
the OLD ref's bin/ tree is checked out on the host first and mounted
read-only alongside the current repo instead. See docker/dev/ab_m2.sh.

Usage: ab_M2.py <old_bin_dir> <new_bin_dir> <old_ref>
"""
from __future__ import annotations
import json, os, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))
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

def run_profile(bin_dir, fixture_binary, store):
    """rat-profile prints its rat.tool-result/v1 envelope to stdout; unlike
    contracts.execute() it never persists the envelope itself as an artifact
    (only the profile/string-index artifacts it references are stored), so
    rat-metrics.iter_tool_results() can't discover it from the store. Parse
    stdout directly instead."""
    p = subprocess.run([os.path.join(bin_dir, "rat-profile"), fixture_binary, "--store", store, "--format", "json"],
                        check=True, capture_output=True, text=True)
    return json.loads(p.stdout)

def measure(bin_dir, name, source):
    with tempfile.TemporaryDirectory() as td:
        src, binp = os.path.join(td, name + ".c"), os.path.join(td, name)
        with open(src, "w") as f:
            f.write(source)
        build(src, binp)
        store = os.path.join(td, "store")
        docs = [run_profile(bin_dir, binp, store), run_profile(bin_dir, binp, store)]  # cold, warm
        return aggregate(docs)

def main():
    if len(sys.argv) != 4:
        print("usage: ab_M2.py <old_bin_dir> <new_bin_dir> <old_ref>", file=sys.stderr)
        return 2
    old_bin, new_bin, old_ref = sys.argv[1], sys.argv[2], sys.argv[3]
    rows = []
    for name, source in FIXTURES.items():
        rows.append({"fixture": name, "old": measure(old_bin, name, source), "new": measure(new_bin, name, source)})

    old_hits = sum(r["old"]["cache_hits"] for r in rows)
    new_hits = sum(r["new"]["cache_hits"] for r in rows)
    old_dup = sum(r["old"]["duplicate_tool_calls"] for r in rows)
    new_dup = sum(r["new"]["duplicate_tool_calls"] for r in rows)
    row = {
        "schema": "rat.session-metrics/v1",
        "ab": "M2-cache-unify",
        "baseline_ref": old_ref,
        "tool": "rat-profile",
        "calls_per_fixture": 2,
        "rows": rows,
        "old_cache_hits_total": old_hits,
        "new_cache_hits_total": new_hits,
        "old_duplicate_tool_calls_total": old_dup,
        "new_duplicate_tool_calls_total": new_dup,
    }
    out_path = os.path.join(os.path.dirname(__file__), "ab_M2.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(row, indent=2, ensure_ascii=False))
    print("wrote", out_path)

if __name__ == "__main__":
    raise SystemExit(main())
