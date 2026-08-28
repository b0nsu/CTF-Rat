"""Deterministic route judgment.

Combines existing rat-profile facts/signals/imports and revq
imports/strings/evasion/interesting into a route label. No new analysis:
every signal consumed here is already computed by rat-profile or revq.

This module is the judgment logic only; the `rat route` front door is
its CLI surface.
"""
from __future__ import annotations

HEAP_IMPORTS = {"malloc", "free", "calloc", "realloc"}
# Unbounded-by-nature sinks: their presence is a strong (fact-grade) overflow signal.
STRONG_OVERFLOW_IMPORTS = {"gets", "strcpy", "strcat", "sprintf",
                          "scanf", "__isoc99_scanf", "__isoc99_sscanf"}
# Sinks that CAN be bounded correctly; presence is only a heuristic overflow signal
# (mirrors recon's `dangerous` set so route stops emitting `unknown` for read(0,buf,N)).
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
    """Score from imports, using profile protection facts to refine the
    subroute; the caller decides whether this competes with a rev candidate."""
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
    """All pwn subroutes whose import signature is present, best-first. Used to
    surface sibling alternatives when e.g. heap AND format+input sinks coexist
    -- the primary is _pwn_candidate's pick; the rest become `alternatives`."""
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

def route(*, profile=None, revq=None, interesting=None):
    """Judge a route from existing profile/revq artifacts.

    `interesting` is the caller-supplied compute_interesting() result for
    `revq` (revq owns that computation; route() stays a pure combinator).
    """
    imports = _profile_imports(profile) | _revq_imports(revq)
    signals = []
    capabilities = {"profile": profile is not None, "revq": revq is not None}
    # PE/Windows is a rev-only track: pwn-* and pwn-kernel are ELF/Linux shapes, so a
    # coincidental import match must NOT route a PE binary into them. Emit a fact-grade
    # platform signal and suppress the pwn candidates below.
    is_pe = (revq or {}).get("platform") == "pe"
    if is_pe:
        signals.append(_sig("pe-platform", "PE/Windows", "fact"))
    packed = _packed_signal(revq)
    if packed:
        value, quality, confidence = packed
        signals.append(_sig("evasion", value, quality))
        return _pe_next(_result("rev", "rev-packed", confidence, signals, capabilities), is_pe)

    if imports & KERNEL_IMPORTS and not is_pe:
        hit = sorted(imports & KERNEL_IMPORTS)
        signals.append(_sig("kernel-imports", hit, "fact"))
        return _result("pwn", "pwn-kernel", 0.8, signals, capabilities)

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
            return _pe_next(_result("rev", rev_subroute, rev_confidence, signals, capabilities, next_target=rev_target), is_pe)
        pwn_subroute, pwn_confidence, pwn_signals = pwn
        # An explicit compare-call is a strong, mechanical checker signal and keeps
        # priority even when a pwn import signal also exists; a generic "interesting"
        # hit with no compare call is weaker and does not outrank a real pwn signal.
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
        return result

    if pwn is not None:
        pwn_subroute, pwn_confidence, pwn_signals = pwn
        signals.extend(pwn_signals)
        result = _result("pwn", pwn_subroute, pwn_confidence, signals, capabilities)
        # Sibling pwn subroutes (heap vs format vs overflow) can coexist; instead of
        # silently picking the highest-priority one, name the losers as alternatives.
        siblings = [(sr, conf) for sr, conf in _pwn_all_candidates(imports, profile) if sr != pwn_subroute]
        if siblings:
            result["conflict"] = True
            result["alternatives"] = [{"track": "pwn", "subroute": sr, "confidence": conf} for sr, conf in siblings]
        return result

    functions = (revq or {}).get("functions") or []
    fn_names = " ".join(f.get("name", "") for f in functions).lower()
    if any(h in fn_names or h in _strings_blob(revq).lower() for h in VM_HINTS):
        signals.append(_sig("vm-dispatch-hint", [h for h in VM_HINTS if h in fn_names or h in _strings_blob(revq).lower()], "heuristic"))
        return _pe_next(_result("rev", "rev-vm", 0.5, signals, capabilities), is_pe)

    if is_pe:
        # PE with no clear checker/vm/crypto signal still stays on the rev track and
        # points at the dynamic emulator rather than falling through to `unknown`.
        return _pe_next(_result("rev", "rev-symbolic", 0.4, signals, capabilities), is_pe)
    return _result("unknown", "unknown", 0.0, signals, capabilities)

def _result(track, subroute, confidence, signals, capabilities, next_target=None):
    return {
        "schema": "rat.route-result/v1",
        "track": track,
        "subroute": subroute,
        "confidence": confidence,
        "signals": signals,
        "capabilities": capabilities,
        "skill": subroute if subroute in SKILLS else None,
        "next": _next_hint(subroute, next_target),
    }

_NEXT_QUERY = {
    "rev-checker": "revq --func",
    "rev-vm": "solve/_template/rev/vmlift.py --disasm",
    "rev-packed": "gdbq",
    "rev-symbolic": "solve/_template/rev/symsolve.py --find-str",
    "pwn-stack": "pwncalc + pwnropcheck",
    "pwn-format": "pwnleak",
    "pwn-heap": "gdbq",
    "pwn-rop": "pwnropcheck",
    "pwn-kernel": "k_dump_heap",
    "unknown": "revq/recon",
}

_NEXT_TARGET = {
    "rev-packed": "dynamic-unpack-trace-before-static-re-analysis",
    "pwn-stack": "no-nx-shellcode-path",
    "pwn-format": "format-string-output",
    "pwn-heap": "heap-breakpoints",
    "pwn-rop": "nx-rop-chain",
    "pwn-kernel": "kernel-tooling",
    "unknown": "more-signal-before-routing",
}

def _next_hint(subroute, target=None):
    query = _NEXT_QUERY.get(subroute, "revq/recon")
    return [{"query": query, "target": target if target is not None else _NEXT_TARGET.get(subroute)}]

def _pe_next(result, is_pe):
    """For PE binaries, append the Qiling dynamic-emulation hint to the next steps
    (static stays decomp/revq; dynamic goes through qiling_trace.py, not gdbq/wine)."""
    if is_pe:
        result.setdefault("next", []).append(
            {"query": "solve/_template/rev/qiling_trace.py", "target": "pe-dynamic-emulation-rootfs-required"}
        )
    return result
