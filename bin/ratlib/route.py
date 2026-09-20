"""Deterministic route judgment with an explicit active-triage overlay.

Combines existing rat-profile facts/signals/imports and revq
imports/strings/evasion_signals/interesting into a *provisional* route
suggestion. No new analysis is performed here: every signal consumed here is
already computed by rat-profile or revq.

`track`/`subroute`/`confidence` remain for compatibility ONLY. They are
not a calibrated probability or a proof that one mutually-exclusive challenge
class has been identified.  The model-facing commitment gate is:

    commitment == "committed"  -> route-specific skill may be loaded
    commitment == "provisional" -> run one cheap discriminating probe first
    commitment == "unknown"     -> collect more bounded evidence first

The `dimensions` projection deliberately separates vulnerability surfaces,
program shapes, analysis obstacles, and exploitation constraints so orthogonal
facts are not collapsed into one categorical route.  On conflicts it projects
both the primary route and every named alternative; the compatibility label is
still singular, but the model-facing working set is not.
"""
from __future__ import annotations

import re

from ratlib.evasion import SIGNAL_SCHEMA as EVASION_SIGNAL_SCHEMA

HEAP_IMPORTS = {"malloc", "free", "calloc", "realloc"}
STRONG_OVERFLOW_IMPORTS = {"gets", "strcpy", "strcat", "sprintf",
                          "scanf", "__isoc99_scanf", "__isoc99_sscanf"}
WEAK_OVERFLOW_IMPORTS = {"read", "memcpy", "fgets", "fread"}
OVERFLOW_IMPORTS = STRONG_OVERFLOW_IMPORTS | WEAK_OVERFLOW_IMPORTS
FORMAT_IMPORTS = {"printf", "fprintf", "dprintf", "syslog"}
INPUT_IMPORTS = {"read", "gets", "scanf", "fgets"}
KERNEL_IMPORTS = {"copy_from_user", "copy_to_user", "kmalloc", "kfree", "module_init", "module_exit"}
VM_HINTS = ("vm", "opcode", "bytecode", "dispatch", "interpreter")
CRYPTO_HINTS = ("aes", "des", "rc4", "md5", "sha", "base64", "xor", "rsa", "hmac", "crc")
# Stable compare APIs used by revq's interesting-function scorer. Route consumes
# revq's structured functions[].calls, never the scorer's human-readable `why`
# strings, so localization/rendering changes cannot alter routing semantics.
CHECKER_COMPARE_CALLS = {
    "strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp", "strstr",
    "strcoll", "bcmp", "wcscmp", "wcsncmp",
}
# A custom checker need not call libc compare APIs (XOR/rolling checks commonly do
# not). Pairing success+failure strings already xref-attributed to the SAME revq
# function is a bounded checker-shape heuristic. These regexes classify binary
# strings, not renderer prose, and never establish checker semantics by themselves.
CHECKER_SUCCESS_STR = re.compile(
    r"correct|success|granted|accept(?:ed)?|congrat|nice|good\s*job|unlock|welcome|\bvalid\b|flag\{",
    re.I,
)
CHECKER_FAILURE_STR = re.compile(
    r"incorrect|wrong|denied|reject(?:ed)?|invalid|fail(?:ed|ure)?|try\s*again",
    re.I,
)

# Installed route-skill inventory. Commitment is a property of each route result,
# not of the inventory: callers that inspect SKILLS must continue to see every
# installed skill, while result["skill"] stays None until the commitment gate
# below allows that specific route to lock one.
SKILLS = {
    "rev-checker", "rev-vm", "rev-packed", "rev-symbolic",
    "pwn-stack", "pwn-format", "pwn-heap", "pwn-rop", "pwn-kernel",
}


def _fact(profile, kind, default=None):
    for f in (profile or {}).get("facts", []) or []:
        if f.get("kind") == kind:
            return f.get("value")
    return default


def _profile_imports(profile):
    return set((profile or {}).get("imports", []) or [])


def _revq_imports(revq):
    return set((revq or {}).get("imports", []) or [])


def _function_record(revq, function_name):
    if not isinstance(function_name, str) or not function_name:
        return None
    return next((func for func in (revq or {}).get("functions", []) or []
                 if isinstance(func, dict) and func.get("name") == function_name), None)


def _function_calls(revq, function_name):
    """Return canonical calls recovered for one exact revq function record."""
    func = _function_record(revq, function_name)
    if func is None:
        return set()
    return {
        call.split("@", 1)[0]
        for call in (func.get("calls", []) or [])
        if isinstance(call, str) and call
    }


def _checker_compare_calls(revq, function_name):
    return sorted(_function_calls(revq, function_name) & CHECKER_COMPARE_CALLS)


def _checker_oracle_strings(revq, function_name):
    """Return a bounded paired success/failure string projection for one function."""
    func = _function_record(revq, function_name)
    if func is None:
        return None
    strings = [value for value in (func.get("strings", []) or []) if isinstance(value, str)]
    success = sorted({value for value in strings if CHECKER_SUCCESS_STR.search(value)})
    failure = sorted({value for value in strings if CHECKER_FAILURE_STR.search(value)})
    if not success or not failure:
        return None
    return {
        "success_count": len(success), "failure_count": len(failure),
        "success": success[:2], "failure": failure[:2],
    }


def _typed_evasion(revq):
    """Return current typed evasion observations; legacy prose is never parsed."""
    doc = revq or {}
    if doc.get("evasion_signal_schema") != EVASION_SIGNAL_SCHEMA:
        return []
    return [
        signal for signal in (doc.get("evasion_signals", []) or [])
        if isinstance(signal, dict)
        and isinstance(signal.get("kind"), str)
        and signal.get("quality") in {"fact", "heuristic"}
    ]


def _packed_signal(revq):
    """Return the strongest typed packing observation and its route rank.

    A concrete packer section outranks entropy even when both are present.
    Human-readable `revq.evasion` text is compatibility output only and cannot
    affect routing.
    """
    observations = _typed_evasion(revq)
    for signal in observations:
        if signal.get("kind") == "packer-section" and signal.get("quality") == "fact":
            return signal, 0.85
    for signal in observations:
        if signal.get("kind") == "high-entropy" and signal.get("quality") == "heuristic":
            return signal, 0.55
    return None


def _strings_blob(revq):
    return " ".join(s.get("val", "") for s in (revq or {}).get("strings", []) or [])


def _sig(kind, value, quality):
    return {"kind": kind, "value": value, "quality": quality}


def _pwn_candidate(imports, profile):
    """Rank import-derived PWN attention candidates.

    These candidates are intentionally provisional. Import presence can select
    the cheapest next probe, but it never establishes an unsafe callsite or a
    runtime primitive by itself.
    """
    if imports & HEAP_IMPORTS:
        hit = sorted(imports & HEAP_IMPORTS)
        return "pwn-heap", 0.55, [_sig("heap-imports", hit, "fact")]
    if (imports & FORMAT_IMPORTS) and (imports & INPUT_IMPORTS):
        hit = sorted(imports & (FORMAT_IMPORTS | INPUT_IMPORTS))
        return "pwn-format", 0.55, [_sig("format-input-imports", hit, "fact")]
    if imports & OVERFLOW_IMPORTS:
        hit = sorted(imports & OVERFLOW_IMPORTS)
        strong = bool(imports & STRONG_OVERFLOW_IMPORTS)
        quality = "fact" if strong else "heuristic"
        confidence = 0.6 if strong else 0.5
        sigs = [_sig("overflow-imports", hit, quality)]
        nx = _fact(profile, "elf.nx")
        if nx is True:
            sigs.append(_sig("elf-nx", True, "fact"))
            return "pwn-rop", confidence, sigs
        return "pwn-stack", confidence, sigs
    return None


def _pwn_all_candidates(imports, profile):
    out = []
    if imports & HEAP_IMPORTS:
        out.append(("pwn-heap", 0.55))
    if (imports & FORMAT_IMPORTS) and (imports & INPUT_IMPORTS):
        out.append(("pwn-format", 0.55))
    if imports & OVERFLOW_IMPORTS:
        strong = bool(imports & STRONG_OVERFLOW_IMPORTS)
        confidence = 0.6 if strong else 0.5
        subroute = "pwn-rop" if _fact(profile, "elf.nx") is True else "pwn-stack"
        out.append((subroute, confidence))
    return out


def _signal_quality(result, kind):
    return next((s.get("quality") for s in result.get("signals", []) if s.get("kind") == kind), None)


def _append_unique(items, value):
    if value not in items:
        items.append(value)


def _candidate_subroutes(result):
    """Return primary + alternatives in deterministic ranking order, deduped."""
    out = []
    for subroute in [result.get("subroute")] + [
        item.get("subroute") for item in result.get("alternatives", []) or []
        if isinstance(item, dict)
    ]:
        if subroute and subroute not in out:
            out.append(subroute)
    return out


def _project_subroute_dimension(subroute, dims, unresolved):
    """Project one ranked candidate without changing commitment or route rank."""
    if subroute == "unknown":
        _append_unique(unresolved, "insufficient deterministic evidence to select a bounded first probe")
    elif subroute == "pwn-heap":
        _append_unique(dims["vulnerability_surfaces"], "heap-lifetime-candidate")
        _append_unique(unresolved, "allocator imports do not prove UAF/double-free/overlap or attacker-controlled lifetime")
    elif subroute == "pwn-format":
        _append_unique(dims["vulnerability_surfaces"], "format-string-candidate")
        _append_unique(unresolved, "prove attacker control reaches a format argument before treating this as format-string")
    elif subroute in {"pwn-stack", "pwn-rop"}:
        _append_unique(dims["vulnerability_surfaces"], "stack-overwrite-candidate")
        _append_unique(unresolved, "prove a concrete overwrite/PC-control primitive; import presence alone is insufficient")
        if subroute == "pwn-rop":
            _append_unique(dims["constraints"], "nx")
            _append_unique(unresolved, "ROP is only an exploitation strategy candidate after control-flow influence is measured")
    elif subroute == "pwn-kernel":
        _append_unique(dims["program_shapes"], "kernel-candidate")
        _append_unique(unresolved, "kernel imports do not prove a kernel module/target environment; inspect the supplied artifact and boot setup")
    elif subroute == "rev-checker":
        _append_unique(dims["program_shapes"], "checker")
        _append_unique(unresolved, "checker semantics and success/failure oracle remain unverified")
    elif subroute == "rev-vm":
        _append_unique(dims["program_shapes"], "vm-candidate")
        _append_unique(unresolved, "VM naming/string hints do not prove a dispatch loop or bytecode semantics")
    elif subroute == "rev-packed":
        _append_unique(dims["obstacles"], "packing")
        _append_unique(unresolved, "packing is an analysis obstacle; underlying checker/VM/other program shape remains open")
    elif subroute == "rev-symbolic":
        _append_unique(dims["program_shapes"], "symbolic-candidate")
        _append_unique(unresolved, "generic interesting/crypto hints do not justify symbolic execution before an oracle is bounded")


def _active_triage_overlay(result):
    """Project ranked compatibility labels into a multi-axis triage state.

    The primary subroute still owns compatibility ranking and the commitment
    decision. The model-facing dimensions, however, include every explicit
    alternative so a conflict cannot silently collapse orthogonal evidence back
    to the primary label that won the ranking tie-break.
    """
    subroute = result.get("subroute")
    dims = {"vulnerability_surfaces": [], "program_shapes": [], "obstacles": [], "constraints": []}
    unresolved = []
    commitment = "provisional"

    for candidate in _candidate_subroutes(result):
        _project_subroute_dimension(candidate, dims, unresolved)

    if subroute == "unknown":
        commitment = "unknown"
    # Static packer-section names, imports and compare calls are observations,
    # not proofs of the underlying class or a validated unpacking procedure.
    # No static-only route is eligible to lock a route-specific skill.

    if any(s.get("kind") == "pe-platform" for s in result.get("signals", [])):
        _append_unique(dims["constraints"], "pe-windows")
    if result.get("conflict"):
        commitment = "provisional"
        conflict_note = "contradictory evidence requires a discriminating probe before any skill lock"
        if conflict_note in unresolved:
            unresolved.remove(conflict_note)
        unresolved.insert(0, conflict_note)

    result["commitment"] = commitment
    result["dimensions"] = dims
    result["unresolved"] = unresolved
    result["score_semantics"] = "heuristic-rank-not-probability"
    result["skill"] = subroute if commitment == "committed" and subroute in SKILLS else None
    return result


def _early_route_context(result, imports, profile, revq, interesting, *, is_pe=False):
    """Project independent observed leads without inventing secondary scores.

    Packer detection is an action/obstacle; kernel imports describe a possible
    program shape. Neither is evidence that all other analysis dimensions are
    false. Compatibility primary/subroute remain stable, but only genuine
    competing *interpretations* belong in alternatives/conflict.
    """
    result = _finalize(result, is_pe)
    observed = []
    if not is_pe:
        if imports & KERNEL_IMPORTS:
            observed.append("pwn-kernel")
        observed.extend(subroute for subroute, _ in _pwn_all_candidates(imports, profile))
    for item in interesting or []:
        func = item.get("func")
        if not func or _function_record(revq, func) is None:
            continue
        if _checker_compare_calls(revq, func) or _checker_oracle_strings(revq, func):
            observed.append("rev-checker")
        else:
            observed.append("rev-symbolic")
    functions = (revq or {}).get("functions") or []
    fn_names = " ".join(f.get("name", "") for f in functions if isinstance(f, dict)).lower()
    if any(h in fn_names or h in _strings_blob(revq).lower() for h in VM_HINTS):
        observed.append("rev-vm")
    # 'leads' are independent, potentially coexisting analysis surfaces. Do
    # not misrepresent them as conflicting or give them fabricated confidence.
    result["leads"] = []
    for subroute in observed:
        if subroute != result["subroute"] and subroute not in result["leads"]:
            result["leads"].append(subroute)
            _project_subroute_dimension(subroute, result["dimensions"], result["unresolved"])
    # Preserve bounded, executable next-probe suggestions for independent
    # leads, but do not issue an instruction to run every one in this order.
    for subroute in result["leads"]:
        for hint in _next_hint(subroute):
            if hint not in result["next"]:
                result["next"].append(hint)
    result["next"] = result["next"][:4]
    return result

def _finalize(result, is_pe=False):
    result = _active_triage_overlay(result)
    return _pe_next(result, is_pe)


def route(*, profile=None, revq=None, interesting=None):
    """Rank a route from existing profile/revq artifacts without hard-locking early."""
    imports = _profile_imports(profile) | _revq_imports(revq)
    signals = []
    capabilities = {"profile": profile is not None, "revq": revq is not None}
    is_pe = (revq or {}).get("platform") == "pe"
    if is_pe:
        signals.append(_sig("pe-platform", "PE/Windows", "fact"))

    packed = _packed_signal(revq)
    if packed:
        observation, confidence = packed
        signals.append(_sig(observation["kind"], observation.get("value"), observation["quality"]))
        return _early_route_context(_result("rev", "rev-packed", confidence, signals, capabilities),
                                    imports, profile, revq, interesting, is_pe=is_pe)

    if imports & KERNEL_IMPORTS and not is_pe:
        hit = sorted(imports & KERNEL_IMPORTS)
        signals.append(_sig("kernel-imports", hit, "fact"))
        return _early_route_context(_result("pwn", "pwn-kernel", 0.8, signals, capabilities),
                                    imports, profile, revq, interesting)

    pwn = None if is_pe else _pwn_candidate(imports, profile)
    # A high interesting-function score only orders inspection; it cannot
    # suppress a lower-ranked function with structured checker evidence.
    ranked = [item for item in (interesting or []) if isinstance(item, dict)]
    top = next((item for item in ranked
                if _checker_compare_calls(revq, item.get("func"))
                or _checker_oracle_strings(revq, item.get("func"))),
               ranked[0] if ranked else None)
    if top:
        score = top.get("score", 0)
        compare_calls = _checker_compare_calls(revq, top.get("func"))
        oracle_strings = _checker_oracle_strings(revq, top.get("func"))
        checker_shape = bool(compare_calls or oracle_strings)
        rev_signals = [_sig("revq-interesting", {"func": top.get("func"), "score": score}, "heuristic")]
        if compare_calls:
            rev_signals.append(_sig("compare-calls", compare_calls, "fact"))
        if oracle_strings:
            rev_signals.append(_sig("checker-oracle-strings", oracle_strings, "heuristic"))
        if checker_shape:
            if compare_calls:
                confidence = min(0.5 + score / 20.0, 0.9)
            else:
                confidence = min(0.45 + score / 30.0, 0.75)
            rev_subroute, rev_confidence, rev_target = "rev-checker", confidence, top.get("func")
        else:
            rev_subroute, rev_confidence, rev_target = "rev-symbolic", 0.5, None
            hints = [h for h in CRYPTO_HINTS if h in _strings_blob(revq).lower()]
            if hints:
                rev_signals.append(_sig("crypto-hint", hints, "heuristic"))
        if pwn is None:
            signals.extend(rev_signals)
            return _early_route_context(
                _result("rev", rev_subroute, rev_confidence, signals, capabilities, next_target=rev_target),
                imports, profile, revq, interesting, is_pe=is_pe)

        pwn_subroute, pwn_confidence, pwn_signals = pwn
        # Structured checker evidence warrants an early bounded function query;
        # an unrelated REV score must never outrank PWN by numeric comparison.
        if checker_shape:
            signals.extend(rev_signals)
            result = _result("rev", rev_subroute, rev_confidence, signals, capabilities, next_target=rev_target)
            # A checker shape and PWN import may coexist. They are distinct
            # leads, not mutually-exclusive route evidence.
        else:
            signals.extend(pwn_signals)
            result = _result("pwn", pwn_subroute, pwn_confidence, signals, capabilities)
            # A generic REV attention score does not refute the PWN lead.
        return _early_route_context(result, imports, profile, revq, interesting, is_pe=is_pe)

    if pwn is not None:
        pwn_subroute, pwn_confidence, pwn_signals = pwn
        signals.extend(pwn_signals)
        result = _result("pwn", pwn_subroute, pwn_confidence, signals, capabilities)
        # All coexisting surface leads are added by the common projection.
        return _early_route_context(result, imports, profile, revq, interesting, is_pe=is_pe)

    functions = (revq or {}).get("functions") or []
    fn_names = " ".join(f.get("name", "") for f in functions).lower()
    if any(h in fn_names or h in _strings_blob(revq).lower() for h in VM_HINTS):
        signals.append(_sig("vm-dispatch-hint", [h for h in VM_HINTS if h in fn_names or h in _strings_blob(revq).lower()], "heuristic"))
        return _early_route_context(_result("rev", "rev-vm", 0.5, signals, capabilities),
                                    imports, profile, revq, interesting, is_pe=is_pe)

    if is_pe:
        return _early_route_context(_result("rev", "rev-symbolic", 0.4, signals, capabilities),
                                    imports, profile, revq, interesting, is_pe=is_pe)
    return _early_route_context(_result("unknown", "unknown", 0.0, signals, capabilities),
                                imports, profile, revq, interesting, is_pe=is_pe)


def _result(track, subroute, confidence, signals, capabilities, next_target=None):
    return {
        "schema": "rat.route-result/v1",
        "track": track,
        "subroute": subroute,
        "confidence": confidence,
        "signals": signals,
        "capabilities": capabilities,
        "skill": None,
        "next": _next_hint(subroute, next_target),
    }


_NEXT_QUERY = {
    "rev-checker": "rat query func",
    "rev-vm": "solve/_template/rev/vmlift.py --disasm",
    "rev-packed": "gdbq",
    "rev-symbolic": "rat query oracle",
    "pwn-stack": "rat query pwn",
    "pwn-format": "rat query pwn",
    "pwn-heap": "rat query pwn",
    "pwn-rop": "rat query pwn",
    "pwn-kernel": "rat query pwn",
    "unknown": "revq/recon",
}

_NEXT_TARGET = {
    "rev-checker": "bounded-checker-function-before-commit",
    "rev-symbolic": "success-failure-oracle-before-symbolic",
    "rev-packed": "verify-packer-and-unpack-need-before-dynamic-tracing",
    "rev-vm": "prove-dispatch-loop-before-vm-lift",
    "pwn-stack": "static-capability-then-measure-overwrite",
    "pwn-format": "static-capability-then-prove-format-argument-control",
    "pwn-heap": "static-capability-then-measure-object-lifetime",
    "pwn-rop": "static-capability-then-measure-pc-control-before-gadgets",
    "pwn-kernel": "confirm-kernel-artifact-and-environment-before-kernel-tooling",
    "unknown": "more-signal-before-routing",
}


def _next_hint(subroute, target=None):
    query = _NEXT_QUERY.get(subroute, "revq/recon")
    return [{"query": query, "target": target if target is not None else _NEXT_TARGET.get(subroute)}]


def _pe_next(result, is_pe):
    """For PE binaries, append a bounded dynamic-emulation discriminator."""
    if is_pe:
        result.setdefault("next", []).append(
            {"query": "solve/_template/rev/qiling_trace.py", "target": "pe-dynamic-emulation-rootfs-required"}
        )
    return result
