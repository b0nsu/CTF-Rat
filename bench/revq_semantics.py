"""Stable, bounded semantic projection of a revq revmap for CFG experiments."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]


def _revq_module():
    path = REPO / "bin" / "revq"
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    loader = importlib.machinery.SourceFileLoader("_bench_revq", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def project(rev: dict) -> dict:
    """Keep addresses, xref sites, oracle candidates, and call relationships.

    String text is retained because two different strings can have the same
    address in malformed or multi-object inputs; callers compare by address and
    content.  The source binary path and timestamps are intentionally omitted.
    """
    revq = _revq_module()
    functions = []
    for func in rev.get("functions", []):
        sites = [{"block_address": s.get("block_address"),
                  "instruction_address": s.get("instruction_address"),
                  "api": s.get("api"), "target_address": s.get("target_address"),
                  "target_kind": s.get("target_kind"),
                  "length_argument": s.get("length_argument")}
                 for s in func.get("call_sites", [])]
        functions.append({
            "addr": func.get("addr"), "name": func.get("name"),
            "size": func.get("size"), "nblocks": func.get("nblocks"),
            "ninstr": func.get("ninstr"), "ncallers": func.get("ncallers"),
            "calls": sorted(func.get("calls", [])),
            "call_sites": sorted(sites, key=lambda s: (s["block_address"] or -1, s["api"] or "")),
            "strings": sorted(func.get("strings", [])),
        })
    strings = [{"addr": s.get("addr"), "val": s.get("val"),
                "xrefs": sorted(({"addr": x.get("addr"), "func": x.get("func")}
                                  for x in s.get("xrefs", [])),
                                 key=lambda x: (x["addr"] or -1, x["func"] or ""))}
               for s in rev.get("strings", [])]
    result = {
        "schema": "rat.revq-semantics/v1",
        "input_sha256": "sha256:" + rev["sha256"],
        "engine": rev.get("engine"), "analysis_status": rev.get("analysis_status"),
        "analysis_complete": rev.get("analysis_complete"),
        "function_count": revq.annotate_counts(rev)["counts"]["functions_total"],
        "functions": sorted(functions, key=lambda f: (f["addr"] or -1, f["name"] or "")),
        "strings": sorted(strings, key=lambda s: (s["addr"] or -1, s["val"] or "")),
        "oracle": revq.compute_oracle(rev),
    }
    if "string_reference_probe" in rev:
        result["string_reference_probe"] = rev["string_reference_probe"]
    return result


def compare(baseline: dict, candidate: dict) -> dict:
    """Report lost/gained xref sites and function/call edges, not just counts."""
    def xrefs(doc):
        return {(s["addr"], s["val"], x["addr"], x["func"])
                for s in doc["strings"] for x in s["xrefs"]}

    def functions(doc):
        return {(f["addr"], f["name"]) for f in doc["functions"]}

    def calls(doc):
        return {(f["addr"], s["block_address"], s["instruction_address"],
                 s["api"], s["target_address"])
                for f in doc["functions"] for s in f["call_sites"]}

    def diff(a, b):
        return {"baseline": len(a), "candidate": len(b),
                "lost": [list(x) for x in sorted(a - b, key=str)],
                "gained": [list(x) for x in sorted(b - a, key=str)]}

    before_functions = {f["addr"]: f for f in baseline["functions"]}
    after_functions = {f["addr"]: f for f in candidate["functions"]}
    changed = [{"addr": addr,
                "fields": sorted(key for key in before_functions[addr]
                                 if before_functions[addr][key] != after_functions[addr][key])}
               for addr in sorted(before_functions.keys() & after_functions.keys())
               if before_functions[addr] != after_functions[addr]]
    method_refs = candidate.get("string_reference_probe", [])
    candidate_pairs = {(s["addr"], x["func"])
                       for s in candidate["strings"] for x in s["xrefs"]}
    method_pairs = {(item["addr"], item["func"]) for item in method_refs}
    return {
        "input_sha256_equal": baseline["input_sha256"] == candidate["input_sha256"],
        "xrefs": diff(xrefs(baseline), xrefs(candidate)),
        "functions": diff(functions(baseline), functions(candidate)),
        "call_sites": diff(calls(baseline), calls(candidate)),
        "oracle_equal": baseline["oracle"] == candidate["oracle"],
        "function_details_equal": baseline["functions"] == candidate["functions"],
        "changed_function_details": changed,
        "string_references_method": {
            "address_function_pairs": len(method_pairs),
            "xref_address_function_pairs": len(candidate_pairs),
            "missing_pairs": [list(x) for x in sorted(candidate_pairs - method_pairs)],
            "extra_pairs": [list(x) for x in sorted(method_pairs - candidate_pairs)],
            "instruction_addresses_available": False,
        } if "string_reference_probe" in candidate else None,
    }
