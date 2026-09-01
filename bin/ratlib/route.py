"""Deterministic route judgment with an explicit active-triage overlay.

Combines existing rat-profile facts/signals/imports and revq
imports/strings/evasion/interesting into a *provisional* route suggestion. No
new analysis is performed here: every signal consumed here is already computed
by rat-profile or revq.

`track`/`subroute`/`confidence` remain for compatibility and ranking.  They are
not a calibrated probability or a proof that one mutually-exclusive challenge
class has been identified.  The model-facing commitment gate is:

    commitment == "committed"  -> route-specific skill may be loaded
    commitment == "provisional" -> run one cheap discriminating probe first
    commitment == "unknown"     -> collect more bounded evidence first

The `dimensions` projection deliberately separates vulnerability surfaces,
program shapes, analysis obstacles, and exploitation constraints so orthogonal
facts are not collapsed into one categorical route.
"""
from __future__ import annotations

HEAP_IMPORTS = {"malloc", "free", "calloc", "realloc"}
# Unbounded-by-nature sinks: presence is strong attention evidence, but still not
# callsite proof that attacker-controlled data reaches an unsafe invocation.
STRONG_OVERFLOW_IMPORTS = {"gets", "strcpy", "strcat", "sprintf",
                          "scanf", "__isoc99_scanf", "__isoc99_sscanf"}
# Sinks that CAN be bounded correctly; presence is only a heuristic overflow signal.
WEAK_OVERFLOW_IMPORTS = {"read", "memcpy", "fgets", "fread"}
OVERFLOW_IMPORTS = STRONG_OVERFLOW_IMPORTS | WEAK_OVERFLOW_IMPORTS
FORMAT_IMPORTS = {"printf", "fprintf", "dprintf", "syslog"}
INPUT_IMPORTS = {"read", "gets", "scanf", "fgets"}
KERNEL_IMPORTS = {"copy_from_user", "copy_to_user", "kmalloc", "kfree", "module_init", "module_exit"}
VM_HINTS = ("vm", "opcode", "bytecode", "dispatch", "interpreter")
CRYPTO_HINTS = ("aes", "des", "rc4", "md5", "sha", "base64", "xor", "rsa", "hmac", "crc")

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


def _evasion(revq):
    return (revq or {}).get("evasion", []) or []


def _packed_signal(revq):
    for e in _evasion(revq):
        text = e.lower()
        if "upx" in text or "패커 섹션" in e or "packed" in text:
            return e, "fact", 0.85
        if "엔트로피" in e:
            return e, "heuristic", 0.55
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
            # Compatibility label only: NX is an exploitation constraint, not a
            # vulnerability class. `dimensions` below keeps that distinction.
            return "pwn-rop", confidence, sigs
        return "pwn-stack", confidence, sigs
    return None


def _pwn_all_candidates(imports, profile):
    """All import-derived PWN candidates, best-first."""
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


def _active_triage_overlay(result):
    """Project a categorical compatibility label into multi-axis triage state."""
    subroute = result.get("subroute")
    dims = {"vulnerability_surfaces": [], "program_shapes": [], "obstacles": [], "constraints": []}
    unresolved = []
    commitment = "provisional"

    if subroute == "unknown":
        commitment = "unknown"
        unresolved.append("insufficient deterministic evidence to select a bounded first probe")
    elif subroute == "pwn-heap":
        dims["vulnerability_surfaces"].append("heap-lifetime-candidate")
        unresolved.append("allocator imports do not prove UAF/double-free/overlap or attacker-controlled lifetime")
    elif subroute == "pwn-format":
        dims["vulnerability_surfaces"].append("format-string-candidate")
        unresolved.append("prove attacker control reaches a format argument before treating this as format-string")
    elif subroute in {"pwn-stack", "pwn-rop"}:
        dims["vulnerability_surfaces"].append("stack-overwrite-candidate")
        unresolved.append("prove a concrete overwrite/PC-control primitive; import presence alone is insufficient")
        if subroute == "pwn-rop":
            dims["constraints"].append("nx")
            unresolved.append("ROP is only an exploitation strategy candidate after control-flow influence is measured")
    elif subroute == "pwn-kernel":
        dims["program_shapes"].append("kernel-module")
        # Kernel-only API imports are a sufficiently discriminating execution
        # domain signal to select the kernel skill, though no exploit primitive is
        # implied by that commitment.
        commitment = "committed"
        unresolved.append("kernel object lifetime and copy_to/from_user semantics still require direct measurement")
    elif subroute == "rev-checker":
        dims["program_shapes"].append("checker")
        # A mechanically detected compare-calling interesting function is enough
        # to choose the bounded checker skill when no competing route survives.
        commitment = "committed"
        unresolved.append("checker semantics and success/failure oracle remain unverified")
    elif subroute == "rev-vm":
        dims["program_shapes"].append("vm-candidate")
        unresolved.append("VM naming/string hints do not prove a dispatch loop or bytecode semantics")
    elif subroute == "rev-packed":
        dims["obstacles"].append("packing")
        # A fact-grade UPX/packer signal safely commits the *next action* to
        # unpacking. Entropy-only suspicion remains provisional.
        commitment = "committed" if _signal_quality(result, "evasion") == "fact" else "provisional"
        unresolved.append("packing is an analysis obstacle; underlying checker/VM/other program shape remains open")
    elif subroute == "rev-symbolic":
        dims["program_shapes"].append("symbolic-candidate")
        unresolved.append("generic interesting/crypto hints do not justify symbolic execution before an oracle is bounded")

    if any(s.get("kind") == "pe-platform" for s in result.get("signals", [])):
        dims["constraints"].append("pe-windows")
    if result.get("conflict"):
        commitment = "provisional"
        unresolved.insert(0, "multiple plausible routes remain; run one cheap discriminating probe before loading a route-specific skill")

    result["commitment"] = commitment
    result["dimensions"] = dims
    result["unresolved"] = unresolved
    result["score_semantics"] = "heuristic-rank-not-probability"
    # This is the actual commitment gate. Keep subroute as the compatibility
    # suggestion, but do not expose a route-specific skill until the evidence is
    # strong enough to commit.
    result["skill"] = subroute if commitment == "committed" and subroute in SKILLS else None
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
        value, quality, confidence = packed
        signals.append(_sig("evasion", value, quality))
        return _finalize(_result("rev", "rev-packed", confidence, signals, capabilities), is_pe)

    if imports & KERNEL_IMPORTS and not is_pe:
        hit = sorted(imports & KERNEL_IMPORTS)
        signals.append(_sig("kernel-imports", hit, "fact"))
        return _finalize(_result("pwn", "pwn-kernel", 0.8, signals, capabilities))

    pwn = None if is_pe else _pwn_candidate(imports, profile)
    top = (interesting or [None])[0] if interesting else None
    if top:
        score = top.get("score", 0)
        why = top.get("why", [])
        calls_cmp = any("비교함수 호출" in w for w in why)
        rev_signals = [_sig("revq-interesting", {"func": top.get("func"), "score": score}, "heuristic")]
        if calls_cmp:
            rev_subroute, rev_confidence, rev_target = "rev-checker", min(0.5 + score / 20.0, 0.9), top.get("func")
        else:
            rev_subroute, rev_confidence, rev_target = "rev-symbolic", 0.5, None
            hints = [h for h in CRYPTO_HINTS if h in _strings_blob(revq).lower()]
            if hints:
                rev_signals.append(_sig("crypto-hint", hints, "heuristic"))
        if pwn is None:
            signals.extend(rev_signals)
            return _finalize(_result("rev", rev_subroute, rev_confidence, signals, capabilities, next_target=rev_target), is_pe)

        pwn_subroute, pwn_confidence, pwn_signals = pwn
        # Keep a deterministic primary suggestion for compatibility, but surface
        # the competing route and force commitment back to provisional below.
        if calls_cmp or rev_confidence >= pwn_confidence:
            signals.extend(rev_signals)
            result = _result("rev", rev_subroute, rev_confidence, signals, capabilities, next_target=rev_target)
            result["conflict"] = True
            result["alternatives"] = [{"track": "pwn", "subroute": pwn_subroute, "confidence": pwn_confidence}]
        else:
            signals.extend(pwn_signals)
            result = _result("pwn", pwn_subroute, pwn_confidence, signals, capabilities)
            result["conflict"] = True
            result["alternatives"] = [{"track": "rev", "subroute": rev_subroute, "confidence": rev_confidence}]
        return _finalize(result, is_pe)

    if pwn is not None:
        pwn_subroute, pwn_confidence, pwn_signals = pwn
        signals.extend(pwn_signals)
        result = _result("pwn", pwn_subroute, pwn_confidence, signals, capabilities)
        siblings = [(sr, conf) for sr, conf in _pwn_all_candidates(imports, profile) if sr != pwn_subroute]
        if siblings:
            result["conflict"] = True
            result["alternatives"] = [{"track": "pwn", "subroute": sr, "confidence": conf} for sr, conf in siblings]
        return _finalize(result, is_pe)

    functions = (revq or {}).get("functions") or []
    fn_names = " ".join(f.get("name", "") for f in functions).lower()
    if any(h in fn_names or h in _strings_blob(revq).lower() for h in VM_HINTS):
        signals.append(_sig("vm-dispatch-hint", [h for h in VM_HINTS if h in fn_names or h in _strings_blob(revq).lower()], "heuristic"))
        return _finalize(_result("rev", "rev-vm", 0.5, signals, capabilities), is_pe)

    if is_pe:
        return _finalize(_result("rev", "rev-symbolic", 0.4, signals, capabilities), is_pe)
    return _finalize(_result("unknown", "unknown", 0.0, signals, capabilities))


def _result(track, subroute, confidence, signals, capabilities, next_target=None):
    return {
        "schema": "rat.route-result/v1",
        "track": track,
        "subroute": subroute,
        "confidence": confidence,
        "signals": signals,
        "capabilities": capabilities,
        # Filled by _active_triage_overlay; initialized here so every internal
        # partial result has the legacy field before finalization.
        "skill": None,
        "next": _next_hint(subroute, next_target),
    }


_NEXT_QUERY = {
    "rev-checker": "rat query func",
    "rev-vm": "solve/_template/rev/vmlift.py --disasm",
    "rev-packed": "gdbq",
    "rev-symbolic": "rat query oracle",
    # Provisional PWN routes deliberately point at evidence-gathering rather than
    # an exploit chain. `rat query pwn` is the bounded static capability frontdoor;
    # runtime primitive proof still belongs to pwncrash/gdbq/state PASS.
    "pwn-stack": "rat query pwn",
    "pwn-format": "rat query pwn",
    "pwn-heap": "rat query pwn",
    "pwn-rop": "rat query pwn",
    "pwn-kernel": "k_dump_heap",
    "unknown": "revq/recon",
}

_NEXT_TARGET = {
    "rev-checker": "bounded-checker-function-before-commit",
    "rev-symbolic": "success-failure-oracle-before-symbolic",
    "rev-packed": "dynamic-unpack-trace-before-static-re-analysis",
    "rev-vm": "prove-dispatch-loop-before-vm-lift",
    "pwn-stack": "static-capability-then-measure-overwrite",
    "pwn-format": "static-capability-then-prove-format-argument-control",
    "pwn-heap": "static-capability-then-measure-object-lifetime",
    "pwn-rop": "static-capability-then-measure-pc-control-before-gadgets",
    "pwn-kernel": "kernel-tooling",
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
