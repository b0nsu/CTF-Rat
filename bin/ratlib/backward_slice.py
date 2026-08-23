"""Small VEX backward slice for branch guards leading to a target block.

This is intentionally not a whole-program taint engine. It resolves temporary
and register definitions inside each predecessor block and reports unresolved
register/stack dependencies rather than inventing inter-block data flow.
"""
from __future__ import annotations

from typing import Any


def _reg_name(arch, offset: int) -> str:
    return str(getattr(arch, "register_names", {}).get(offset, "reg@%d" % offset))


def _const_value(expr) -> int | None:
    con = getattr(expr, "con", None)
    value = getattr(con, "value", None)
    return int(value) if isinstance(value, int) else None


def _children(expr) -> list[Any]:
    try:
        return list(expr.child_expressions)
    except Exception:
        out = []
        for name in ("args", "addr", "data", "cond", "iftrue", "iffalse"):
            value = getattr(expr, name, None)
            if isinstance(value, (list, tuple)):
                out.extend(value)
            elif value is not None and hasattr(value, "tag"):
                out.append(value)
        return out


def _stack_slot(expr, arch) -> str | None:
    """Recognize direct sp/bp +/- constant addresses without symbolic guessing."""
    tag = type(expr).__name__
    if tag == "Get":
        name = _reg_name(arch, int(expr.offset))
        if name in {"rsp", "rbp", "esp", "ebp", "sp", "x29"}:
            return "%s+0" % name
        return None
    args = list(getattr(expr, "args", []) or [])
    if len(args) != 2:
        return None
    left, right = args
    base = _stack_slot(left, arch)
    const = _const_value(right)
    if base is None or const is None:
        base = _stack_slot(right, arch)
        const = _const_value(left)
    if base is None or const is None:
        return None
    opname = str(getattr(expr, "op", ""))
    sign = -1 if "Sub" in opname and _stack_slot(left, arch) is not None else 1
    root = base.split("+", 1)[0]
    disp = sign * const
    return "%s%+d" % (root, disp)


def _expr_uses(expr, arch, tmp_defs, seen_tmps=None) -> tuple[set[str], set[str], list[dict[str, Any]]]:
    seen_tmps = set(seen_tmps or ())
    regs: set[str] = set()
    stack: set[str] = set()
    trace: list[dict[str, Any]] = []
    tag = type(expr).__name__

    if tag == "RdTmp":
        tmp = int(expr.tmp)
        if tmp in seen_tmps:
            return regs, stack, trace
        seen_tmps.add(tmp)
        definition = tmp_defs.get(tmp)
        if definition is None:
            trace.append({"kind": "tmp-unresolved", "tmp": tmp})
            return regs, stack, trace
        r, s, t = _expr_uses(definition["expr"], arch, tmp_defs, seen_tmps)
        regs |= r; stack |= s
        trace.append({"kind": "tmp", "tmp": tmp, "insn": definition["insn"]})
        trace.extend(t)
        return regs, stack, trace

    if tag == "Get":
        regs.add(_reg_name(arch, int(expr.offset)))
        return regs, stack, trace

    if tag == "Load":
        slot = _stack_slot(expr.addr, arch)
        if slot:
            stack.add(slot)
            trace.append({"kind": "stack-load", "slot": slot})
        r, s, t = _expr_uses(expr.addr, arch, tmp_defs, seen_tmps)
        regs |= r; stack |= s; trace.extend(t)
        return regs, stack, trace

    for child in _children(expr):
        r, s, t = _expr_uses(child, arch, tmp_defs, seen_tmps)
        regs |= r; stack |= s; trace.extend(t)
    return regs, stack, trace


def _block_guard_slices(project, node) -> list[dict[str, Any]]:
    block = project.factory.block(node.addr, size=node.size)
    tmp_defs: dict[int, dict[str, Any]] = {}
    reg_defs: dict[str, dict[str, Any]] = {}
    current_insn = node.addr
    out = []

    for idx, stmt in enumerate(block.vex.statements):
        tag = type(stmt).__name__
        if tag == "IMark":
            current_insn = int(stmt.addr) + int(getattr(stmt, "delta", 0) or 0)
            continue
        if tag == "WrTmp":
            tmp_defs[int(stmt.tmp)] = {"expr": stmt.data, "insn": current_insn, "stmt": idx}
            continue
        if tag == "Put":
            name = _reg_name(project.arch, int(stmt.offset))
            reg_defs[name] = {"expr": stmt.data, "insn": current_insn, "stmt": idx}
            continue
        if tag != "Exit":
            continue

        regs, stack, trace = _expr_uses(stmt.guard, project.arch, tmp_defs)
        # Resolve same-block register definitions recursively. This captures the
        # common VEX cc_dep*/flags chain produced by cmp/test before a branch.
        queue = list(sorted(regs)); resolved = set()
        while queue:
            reg = queue.pop()
            if reg in resolved:
                continue
            resolved.add(reg)
            definition = reg_defs.get(reg)
            if not definition:
                continue
            r2, s2, t2 = _expr_uses(definition["expr"], project.arch, tmp_defs)
            regs |= r2; stack |= s2
            trace.append({"kind": "reg-def", "reg": reg, "insn": definition["insn"]})
            trace.extend(t2)
            queue.extend(x for x in r2 if x not in resolved)

        dst = getattr(getattr(stmt, "dst", None), "value", None)
        out.append({
            "branch_insn": current_insn,
            "taken_target": int(dst) if isinstance(dst, int) else None,
            "register_dependencies": sorted(regs),
            "stack_dependencies": sorted(stack),
            "trace": trace[:64],
        })
    return out


def _resolve_function(cfg, target: str):
    try:
        addr = int(target, 0)
    except ValueError:
        addr = None
    if addr is not None:
        func = cfg.kb.functions.get(addr)
        if func is not None:
            return func
    exact = [f for f in cfg.kb.functions.values() if f.name == target]
    if exact:
        return exact[0]
    partial = [f for f in cfg.kb.functions.values() if target.lower() in f.name.lower()]
    if len(partial) == 1:
        return partial[0]
    if len(partial) > 1:
        raise ValueError("ambiguous function: %s" % ", ".join(f.name for f in partial[:8]))
    raise ValueError("function not found: %s" % target)


def slice_to_anchor(binary: str, function: str, anchor: int, *, max_predecessors: int = 8) -> dict[str, Any]:
    try:
        import angr
    except ImportError as exc:
        raise ValueError("angr is required for backward slicing") from exc

    project = angr.Project(binary, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    func = _resolve_function(cfg, function)
    node = cfg.get_any_node(anchor, anyaddr=True)
    if node is None or not (func.addr <= node.addr < func.addr + max(int(func.size or 1), 1)):
        raise ValueError("anchor is not inside the selected function")

    preds = []
    for pred in cfg.graph.predecessors(node):
        if func.addr <= pred.addr < func.addr + max(int(func.size or 1), 1):
            preds.append(pred)
    preds = sorted(preds, key=lambda n: n.addr)[:max_predecessors]

    branches = []
    for pred in preds:
        for item in _block_guard_slices(project, pred):
            item["predecessor_block"] = pred.addr
            item["target_block"] = node.addr
            item["reaches_anchor_block"] = True
            branches.append(item)

    return {
        "schema": "rat.backward-slice/v1",
        "binary": binary,
        "function": {"name": func.name, "addr": func.addr, "size": int(func.size or 0)},
        "anchor": anchor,
        "anchor_block": node.addr,
        "branches": branches,
        "coverage": {
            "scope": "predecessor-block branch guards",
            "tmp_def_use": True,
            "same_block_register_defs": True,
            "direct_stack_slots": True,
            "inter_block_value_flow": False,
            "memory_aliasing": False,
        },
        "note": "reported dependencies are bounded static evidence; unresolved inter-block values are not guessed",
    }
