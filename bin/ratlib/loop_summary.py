"""Bounded natural-loop and affine register recurrence summaries.

This module is intentionally conservative.  It recognizes only natural loops in
one recovered function and only register updates whose per-iteration effect is
an immediate affine delta (add/sub/inc/dec).  Everything else is surfaced as an
unsupported/unknown condition; callers must never treat this output as a proof
or as permission to fast-forward symbolic execution without independent checks.
"""
from __future__ import annotations

import re

SCHEMA = "rat.loop-summary/v1"
VERSION = "loop-summary-mvp/1"
DEFAULT_MAX_BLOCKS = 128
DEFAULT_MAX_LOOPS = 16

_X86_ALIASES = {
    "al":"rax","ah":"rax","ax":"rax","eax":"rax","rax":"rax",
    "bl":"rbx","bh":"rbx","bx":"rbx","ebx":"rbx","rbx":"rbx",
    "cl":"rcx","ch":"rcx","cx":"rcx","ecx":"rcx","rcx":"rcx",
    "dl":"rdx","dh":"rdx","dx":"rdx","edx":"rdx","rdx":"rdx",
    "sil":"rsi","si":"rsi","esi":"rsi","rsi":"rsi",
    "dil":"rdi","di":"rdi","edi":"rdi","rdi":"rdi",
    "bpl":"rbp","bp":"rbp","ebp":"rbp","rbp":"rbp",
    "spl":"rsp","sp":"rsp","esp":"rsp","rsp":"rsp",
}
for _i in range(8, 16):
    _X86_ALIASES.update({
        "r%d" % _i: "r%d" % _i,
        "r%dd" % _i: "r%d" % _i,
        "r%dw" % _i: "r%d" % _i,
        "r%db" % _i: "r%d" % _i,
    })

_REG = r"(?:r(?:1[0-5]|[89])(?:d|w|b)?|r(?:ax|bx|cx|dx|si|di|bp|sp)|e(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][hl]|[abcd]x|[sd]il?|[bs]pl?)"
_IMM = r"[-+]?(?:0x[0-9a-f]+|\d+)"
_UPDATE_PATTERNS = (
    (re.compile(r"^\s*add\s+(%s)\s*,\s*(%s)\s*$" % (_REG, _IMM), re.I), +1),
    (re.compile(r"^\s*sub\s+(%s)\s*,\s*(%s)\s*$" % (_REG, _IMM), re.I), -1),
)
_INCDEC = re.compile(r"^\s*(inc|dec)\s+(%s)\s*$" % _REG, re.I)


def normalize_register(name):
    if not name:
        return None
    return _X86_ALIASES.get(str(name).strip().lower(), str(name).strip().lower())


def _parse_int(value):
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def parse_affine_update(mnemonic, op_str):
    """Return (canonical_register, delta) for a supported immediate update."""
    text = "%s %s" % ((mnemonic or "").strip(), (op_str or "").strip())
    for rx, sign in _UPDATE_PATTERNS:
        m = rx.match(text)
        if m:
            value = _parse_int(m.group(2))
            if value is None:
                return None
            return normalize_register(m.group(1)), sign * value
    m = _INCDEC.match(text)
    if m:
        return normalize_register(m.group(2)), (1 if m.group(1).lower() == "inc" else -1)
    return None


def _raw_insn(wrapper):
    return getattr(wrapper, "insn", wrapper)


def _insn_fields(wrapper):
    raw = _raw_insn(wrapper)
    return (
        getattr(wrapper, "mnemonic", getattr(raw, "mnemonic", "")) or "",
        getattr(wrapper, "op_str", getattr(raw, "op_str", "")) or "",
        getattr(wrapper, "address", getattr(raw, "address", None)),
    )


def _written_registers(wrapper):
    """Best-effort Capstone register-write set; empty means unavailable."""
    raw = _raw_insn(wrapper)
    try:
        _reads, writes = raw.regs_access()
        return {normalize_register(raw.reg_name(reg)) for reg in writes if raw.reg_name(reg)}
    except Exception:
        return set()


def _first_operand_is_memory(op_str):
    first = (op_str or "").split(",", 1)[0]
    return "[" in first and "]" in first


def summarize_instruction_stream(instructions, bit_width=64, internal_branch=False):
    """Conservatively summarize straight-line loop-body register deltas.

    `instructions` may be angr Capstone wrappers or small fakes exposing
    mnemonic/op_str/address and optionally regs_access/reg_name.  The function
    refuses to emit a recurrence for a register if it observes another write to
    that register that is not one of the supported immediate updates.
    """
    updates = {}
    clobbered = set()
    calls = []
    memory_writes = 0
    write_info_available = True

    for insn in instructions:
        mnemonic, op_str, address = _insn_fields(insn)
        mnem = mnemonic.lower()
        if mnem.startswith("call"):
            calls.append(address)
        if _first_operand_is_memory(op_str) and mnem not in {"cmp", "test", "lea"}:
            memory_writes += 1

        affine = parse_affine_update(mnemonic, op_str)
        writes = _written_registers(insn)
        if not writes:
            if affine:
                writes = {affine[0]}
            elif mnem not in {"cmp", "test", "jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "nop"}:
                write_info_available = False

        if affine:
            reg, delta = affine
            updates[reg] = updates.get(reg, 0) + delta
            for reg_written in writes:
                if reg_written and reg_written != reg:
                    clobbered.add(reg_written)
        else:
            clobbered.update(reg for reg in writes if reg)

    unsupported = []
    if internal_branch:
        unsupported.append("internal_branch")
    if calls:
        unsupported.append("call_in_loop")
    if memory_writes:
        unsupported.append("memory_state_unmodeled")
    if not write_info_available:
        unsupported.append("register_write_set_incomplete")

    recurrences = []
    if not internal_branch and not calls and write_info_available:
        for reg, delta in sorted(updates.items()):
            if reg in clobbered or delta == 0:
                continue
            recurrences.append({
                "target": reg,
                "kind": "affine-delta",
                "delta": delta,
                "bit_width": int(bit_width or 64),
                "formula": "%s(N) = %s(0) %s %d*N (mod 2^%d)" % (
                    reg, reg, "+" if delta >= 0 else "-", abs(delta), int(bit_width or 64)),
                "quality": "candidate",
            })
    if not recurrences:
        unsupported.append("no_affine_register_recurrence")

    return {
        "recurrences": recurrences,
        "unsupported": sorted(set(unsupported)),
        "calls": ["%#x" % x if isinstance(x, int) else x for x in calls if x is not None],
        "memory_writes": memory_writes,
        "register_write_set_complete": write_info_available,
    }


def _node_addr(node):
    return getattr(node, "addr", None)


def _dominates(idom, dominator, node):
    cur = node
    seen = set()
    while cur in idom and cur not in seen:
        if cur == dominator:
            return True
        seen.add(cur)
        parent = idom[cur]
        if parent == cur:
            break
        cur = parent
    return cur == dominator


def _natural_loop_nodes(graph, header, latch):
    loop = {header, latch}
    stack = [latch]
    while stack:
        node = stack.pop()
        for pred in graph.predecessors(node):
            if pred not in loop:
                loop.add(pred)
                if pred != header:
                    stack.append(pred)
    return loop


def _detect_natural_loops(graph, start, max_loops):
    import networkx as nx

    idom = nx.immediate_dominators(graph, start)
    found = []
    for src, dst in graph.edges():
        if dst in idom and src in idom and _dominates(idom, dst, src):
            found.append((dst, src, _natural_loop_nodes(graph, dst, src)))
            if len(found) >= max_loops:
                break
    return found


def _collect_instructions(project, nodes):
    instructions = []
    failed = []
    for node in sorted(nodes, key=lambda n: (_node_addr(n) is None, _node_addr(n) or 0)):
        addr = _node_addr(node)
        if addr is None:
            failed.append(None)
            continue
        try:
            instructions.extend(project.factory.block(addr).capstone.insns)
        except Exception:
            failed.append(addr)
    return instructions, failed


def summarize_function_loops(project, func, max_blocks=DEFAULT_MAX_BLOCKS, max_loops=DEFAULT_MAX_LOOPS):
    """Return a bounded `rat.loop-summary/v1` document for one function."""
    arch = getattr(getattr(project, "arch", None), "name", "unknown")
    doc = {
        "schema": SCHEMA,
        "version": VERSION,
        "function": {"name": getattr(func, "name", "?"), "address": "%#x" % getattr(func, "addr", 0)},
        "arch": arch,
        "loops": [],
        "coverage": {"complete": False, "scope": "natural-loops/register-affine", "omitted": []},
        "limitations": [
            "candidate summary only; not a def-use proof",
            "heap/global aliasing and memory recurrences are not modeled",
            "trip counts and exit predicates are not solved",
        ],
    }
    if arch not in {"AMD64", "X86", "x86_64", "i386"}:
        doc["coverage"]["omitted"].append("unsupported_arch")
        return doc

    graph = getattr(func, "graph", None)
    if graph is None or len(graph) == 0:
        doc["coverage"]["omitted"].append("function_graph_unavailable")
        return doc
    if len(graph) > max_blocks:
        doc["coverage"]["omitted"].append("function_block_budget_exceeded")
        doc["coverage"]["block_count"] = len(graph)
        return doc

    start = next((node for node in graph.nodes if _node_addr(node) == getattr(func, "addr", None)), None)
    if start is None:
        try:
            start = next(iter(graph.nodes))
        except StopIteration:
            doc["coverage"]["omitted"].append("function_entry_unavailable")
            return doc

    try:
        natural = _detect_natural_loops(graph, start, max_loops)
    except Exception as exc:
        doc["coverage"]["omitted"].append("dominator_analysis_failed:%s" % type(exc).__name__)
        return doc

    loop_limit_hit = len(natural) >= max_loops
    bit_width = int(getattr(getattr(project, "arch", None), "bits", 64) or 64)
    for header, latch, nodes in natural:
        node_set = set(nodes)
        entry_edges = [(u, v) for u, v in graph.edges() if u not in node_set and v in node_set]
        exit_edges = [(u, v) for u, v in graph.edges() if u in node_set and v not in node_set]
        internal_branch = any(sum(1 for succ in graph.successors(node) if succ in node_set) > 1 for node in node_set)
        instructions, failed_blocks = _collect_instructions(project, node_set)
        body = summarize_instruction_stream(instructions, bit_width=bit_width, internal_branch=internal_branch)
        unsupported = list(body["unsupported"])
        if any(v != header for _u, v in entry_edges):
            unsupported.append("multiple_entry")
        if failed_blocks:
            unsupported.append("block_decode_failed")

        doc["loops"].append({
            "header": "%#x" % (_node_addr(header) or 0),
            "latch": "%#x" % (_node_addr(latch) or 0),
            "block_count": len(node_set),
            "instruction_count": len(instructions),
            "entry_edges": [
                {"from": "%#x" % (_node_addr(u) or 0), "to": "%#x" % (_node_addr(v) or 0)} for u, v in entry_edges
            ],
            "exit_edges": [
                {"from": "%#x" % (_node_addr(u) or 0), "to": "%#x" % (_node_addr(v) or 0)} for u, v in exit_edges
            ],
            "recurrences": body["recurrences"],
            "unsupported": sorted(set(unsupported)),
            "memory_writes": body["memory_writes"],
            "eligible_for_fast_forward": False,
        })

    if loop_limit_hit:
        doc["coverage"]["omitted"].append("loop_count_budget_reached")
    doc["coverage"]["complete"] = not doc["coverage"]["omitted"]
    doc["coverage"]["loop_count"] = len(doc["loops"])
    doc["coverage"]["block_count"] = len(graph)
    return doc
