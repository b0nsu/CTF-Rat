"""Canonical rat-slice entrypoint with bounded loop-summary enrichment.

Call-path mode delegates to ratlib.analysis unchanged.  Data mode keeps the
existing bounded VEX/input-API summary and adds a conservative natural-loop
projection from ratlib.loop_summary.  The added summary is heuristic evidence
only; it never upgrades the slice claim or verification status.
"""
from __future__ import annotations

from . import analysis as base
from .loop_summary import summarize_function_loops


def _parser():
    p = base.parser()
    p.add_argument("--profile", required=True)
    p.add_argument("--from", dest="from_loc")
    p.add_argument("--to", dest="to_loc")
    p.add_argument("--direction", default="forward")
    p.add_argument("--depth", type=int, default=4)
    p.add_argument("--mode", choices=["call-path", "data"], default="call-path")
    p.add_argument("--backward", dest="backward_addr")
    p.add_argument("--source", default=None)
    return p


def _data_slice(a):
    r = base.root(a, a.binary)
    started = base.iso()
    try:
        profile = base.require_profile(a, r)
    except ValueError as exc:
        return base.emit(base.envelope("rat-slice", a.binary, a, {}, status="error",
                                       code=base.EXIT_INPUT, diagnostics=[str(exc)], started=started), a)

    target = base._parse_addr(a.backward_addr)
    if target is None:
        return base.emit(base.envelope("rat-slice", a.binary, a, {"analysis_kind": "data"}, status="error",
                                       code=base.EXIT_INPUT, diagnostics=["--backward requires an address"], started=started), a)
    try:
        import angr
    except ImportError:
        return base.emit(base.envelope("rat-slice", a.binary, a,
                                       {"analysis_kind": "data", "coverage": "unavailable"},
                                       status="partial", diagnostics=["angr dependency missing; no synthetic slice emitted"],
                                       started=started), a)

    try:
        project = angr.Project(a.binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True)
        func = base._data_slice_locate_function(cfg, project, target)
        if func is None:
            return base.emit(base.envelope("rat-slice", a.binary, a,
                                           {"analysis_kind": "data", "coverage": "incomplete"},
                                           status="partial", diagnostics=["target address not found in any recovered function"],
                                           started=started), a)

        registers, stack_local, loads, unresolved_aliases = base._data_slice_scan_registers(project, func, target)
        callgraph = cfg.kb.functions.callgraph

        def callee_names(addr):
            return sorted({cfg.kb.functions[n].name for n in callgraph.successors(addr) if n in cfg.kb.functions}) if addr in callgraph else []

        direct_calls = callee_names(func.addr)
        input_calls = sorted(set(direct_calls) & base.DATA_SLICE_INPUT_APIS)
        depth_budget = max(0, min(int(a.depth or 0), 2))
        callers_by_depth = {}
        frontier = {func.addr}
        seen = {func.addr}
        for depth in range(1, depth_budget + 1):
            nxt = set()
            for addr in frontier:
                if addr in callgraph:
                    nxt |= {p for p in callgraph.predecessors(addr) if p in cfg.kb.functions and p not in seen}
            if not nxt:
                break
            callers_by_depth[depth] = sorted(cfg.kb.functions[n].name for n in nxt)
            seen |= nxt
            frontier = nxt

        unresolved_indirect = 1 if getattr(func, "has_unresolved_calls", False) else 0
        loop_doc = summarize_function_loops(project, func)
        loop_projection = {
            "schema": loop_doc["schema"],
            "coverage": loop_doc["coverage"],
            "loops": loop_doc["loops"],
        }
        within_function = {
            "registers_read": registers,
            "stack_locals_referenced": stack_local,
            "direct_calls": direct_calls,
            "input_api_calls": input_calls,
            "loop_analysis": loop_projection,
        }
        payload = {
            "analysis_kind": "data",
            "source": a.source,
            "target": {"address": "%#x" % target, "function": func.name},
            "within_function": within_function,
            "interproc": {"depth": depth_budget, "callers_by_depth": callers_by_depth},
            "claim": "dependency-candidate",
            "unresolved_aliases": unresolved_aliases,
            "unresolved_indirect_calls": unresolved_indirect,
        }
        loop_artifact = base.artifact(loop_doc, "loop-summary", "loop-summary.json", r)
        diagnostics = [
            "backward data slice is a bounded VEX-text summary, not a proven def-use graph",
            "loop recurrences are conservative candidates, not proof or fast-forward permission",
            "heap/global aliasing and indirect calls are not resolved; see unresolved_* counts",
        ]
        omitted = loop_doc.get("coverage", {}).get("omitted", [])
        if omitted:
            diagnostics.append("loop summary partial: %s" % ", ".join(omitted))
        return base.emit(base.envelope("rat-slice", a.binary, a, payload, [loop_artifact], status="ok",
                                       diagnostics=diagnostics, started=started), a)
    except Exception as exc:
        return base.emit(base.envelope("rat-slice", a.binary, a,
                                       {"analysis_kind": "data", "coverage": "incomplete"},
                                       status="partial", diagnostics=["angr analysis incomplete: %s" % type(exc).__name__],
                                       started=started), a)


def main(argv=None):
    a = _parser().parse_args(argv)
    if a.mode == "data":
        return _data_slice(a)
    return base.slice_(a)
