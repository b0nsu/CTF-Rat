#!/usr/bin/env python3
"""M3-4: measured A/B of revq's oracle-wiring (M3-1) and Function Card v2
(M3-2) against the pre-M3 revq, on the same crackme fixture.

Oracle wiring: before M3, revq's text output never printed xref
*addresses* (only xref function names) -- the only way to get a
symsolve-ready address was `--json` (the full raw revmap, an unbounded
dump). Measures raw_output bytes and dump-call count to reach a
symsolve-ready command: old (forced `--json` dump) vs new (bounded default
summary, ORACLE/SUGGEST lines).

Function Card v2: before M3, the same single-function facts (callers,
calls, strings, interesting score) required 3 separate calls
(--xrefs/--func/--interesting). Measures call count and total stdout bytes:
old (3 calls) vs new (1 `--func` call).

Usage: ab_M3.py <old_bin_dir> <new_bin_dir> <old_ref>
"""
from __future__ import annotations
import json, os, subprocess, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

SOURCE = r'''
#include <unistd.h>
#include <string.h>
#include <stdio.h>
int main(void){char b[16]={0};if(read(0,b,11)<0)return 1;
if(memcmp(b,"s3cr3t_p4ss",11)==0)puts("Correct!");else puts("Wrong!");return 0;}
'''

def build(src_path, bin_path):
    subprocess.run(["gcc", "-O1", "-s", src_path, "-o", bin_path], check=True)

def run(revq, *args):
    p = subprocess.run([revq, *args], check=True, capture_output=True, text=True)
    return p.stdout

def measure(bin_dir, binp):
    revq = os.path.join(bin_dir, "revq")
    # oracle wiring
    summary = run(revq, binp)
    old_json_dump = run(revq, binp, "--json")
    oracle_ready = "SUGGEST symsolve.py" in summary
    oracle_forced_raw_dump = not oracle_ready  # had to fall back to --json to get an address
    oracle_bytes = len(summary.encode()) if oracle_ready else len(old_json_dump.encode())
    oracle_calls = 1 if oracle_ready else 2  # summary (no address) + forced --json

    # function-card equivalent: 3 old calls vs 1 new call, on "main"
    xrefs_out = run(revq, binp, "--xrefs", "main")
    func_out = run(revq, binp, "--func", "main")
    interesting_out = run(revq, binp, "--interesting")
    three_call_bytes = len(xrefs_out.encode()) + len(func_out.encode()) + len(interesting_out.encode())
    try:
        card = json.loads(func_out)
        one_call_is_structured = card.get("schema") == "rat.function-card/v2"
        one_call_bytes = len(func_out.encode())
        one_call_calls = 1
    except ValueError:
        one_call_is_structured = False
        one_call_bytes = three_call_bytes
        one_call_calls = 3

    return {
        "oracle_ready_without_raw_dump": oracle_ready,
        "oracle_forced_raw_json_dump": oracle_forced_raw_dump,
        "oracle_output_bytes": oracle_bytes,
        "oracle_calls_to_ready_command": oracle_calls,
        "function_card_is_structured_v2": one_call_is_structured,
        "function_info_calls": one_call_calls if one_call_is_structured else 3,
        "function_info_bytes": one_call_bytes if one_call_is_structured else three_call_bytes,
        "three_separate_calls_bytes_reference": three_call_bytes,
    }

def main():
    if len(sys.argv) != 4:
        print("usage: ab_M3.py <old_bin_dir> <new_bin_dir> <old_ref>", file=sys.stderr)
        return 2
    old_bin, new_bin, old_ref = sys.argv[1], sys.argv[2], sys.argv[3]
    with tempfile.TemporaryDirectory() as td:
        src, binp = os.path.join(td, "crackme.c"), os.path.join(td, "crackme")
        with open(src, "w") as f:
            f.write(SOURCE)
        build(src, binp)
        old_m, new_m = measure(old_bin, binp), measure(new_bin, binp)

    row = {
        "schema": "rat.session-metrics/v1",
        "ab": "M3-rev-features",
        "baseline_ref": old_ref,
        "fixture": "crackme_memcmp",
        "old": old_m,
        "new": new_m,
        "oracle_bytes_reduction_pct": round(100 * (1 - new_m["oracle_output_bytes"] / old_m["oracle_output_bytes"]), 1) if old_m["oracle_output_bytes"] else None,
        "function_info_calls_reduction": old_m["function_info_calls"] - new_m["function_info_calls"],
        "function_info_bytes_reduction_pct": round(100 * (1 - new_m["function_info_bytes"] / old_m["function_info_bytes"]), 1) if old_m["function_info_bytes"] else None,
        "function_info_note": ("bytes can increase vs. the old 3-terse-calls baseline for a trivial function: "
                                "the v2 card carries oracle_candidates/heuristics/unresolved/provenance the old "
                                "3 calls never had at all (not a like-for-like size comparison). The real win "
                                "M3-2 targets is round-trips: 3 calls -> 1."),
    }
    out_path = os.path.join(os.path.dirname(__file__), "ab_M3.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    print(json.dumps(row, indent=2, ensure_ascii=False))
    print("wrote", out_path)

if __name__ == "__main__":
    raise SystemExit(main())
