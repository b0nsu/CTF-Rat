"""Deterministic route judgment (M1-3).

Combines existing rat-profile facts/signals/imports and revq
imports/strings/evasion/interesting into a route label. No new analysis:
every signal consumed here is already computed by rat-profile or revq.

CLI exposure is deferred to M4's `rat route` front door (ADR-007,
single front door) -- this module is the judgment logic only.
"""
from __future__ import annotations

HEAP_IMPORTS = {"malloc", "free", "calloc", "realloc"}
OVERFLOW_IMPORTS = {"gets", "strcpy", "strcat", "sprintf"}
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

def _is_packed(revq):
    for e in _evasion(revq):
        if "패커" in e or "엔트로피" in e or "packed" in e.lower() or "upx" in e.lower():
            return e
    return None

def _strings_blob(revq):
    return " ".join(s.get("val", "") for s in (revq or {}).get("strings", []) or [])

def route(*, profile=None, revq=None, interesting=None):
    """Judge a route from existing profile/revq artifacts.

    `interesting` is the caller-supplied compute_interesting() result for
    `revq` (revq owns that computation; route() stays a pure combinator).
    """
    imports = _profile_imports(profile) | _revq_imports(revq)
    signals = []
    capabilities = {"profile": profile is not None, "revq": revq is not None}
    packed = _is_packed(revq)
    if packed:
        signals.append("evasion: " + packed)
        return _result("rev", "rev-packed", 0.85, signals, capabilities)

    if imports & KERNEL_IMPORTS:
        hit = sorted(imports & KERNEL_IMPORTS)
        signals.append("kernel imports: " + ",".join(hit))
        return _result("pwn", "pwn-kernel", 0.8, signals, capabilities)

    top = (interesting or [None])[0] if interesting else None
    if top:
        score = top.get("score", 0)
        why = top.get("why", [])
        calls_cmp = any("비교함수 호출" in w for w in why)
        signals.append("revq interesting top func=%s score=%s" % (top.get("func"), score))
        if calls_cmp:
            confidence = min(0.5 + score / 20.0, 0.9)
            return _result("rev", "rev-checker", confidence, signals, capabilities)
        if any(h in _strings_blob(revq).lower() for h in CRYPTO_HINTS):
            signals.append("crypto hint in strings")
        return _result("rev", "rev-symbolic", 0.5, signals, capabilities)

    if imports & HEAP_IMPORTS:
        hit = sorted(imports & HEAP_IMPORTS)
        signals.append("heap imports: " + ",".join(hit))
        return _result("pwn", "pwn-heap", 0.55, signals, capabilities)

    if (imports & FORMAT_IMPORTS) and (imports & INPUT_IMPORTS):
        signals.append("format+input imports: " + ",".join(sorted(imports & (FORMAT_IMPORTS | INPUT_IMPORTS))))
        return _result("pwn", "pwn-format", 0.55, signals, capabilities)

    if imports & OVERFLOW_IMPORTS:
        hit = sorted(imports & OVERFLOW_IMPORTS)
        signals.append("overflow-prone imports: " + ",".join(hit))
        nx = _fact(profile, "elf.nx")
        if nx is True:
            signals.append("elf.nx=true -> shellcode blocked")
            return _result("pwn", "pwn-rop", 0.6, signals, capabilities)
        return _result("pwn", "pwn-stack", 0.6, signals, capabilities)

    functions = (revq or {}).get("functions") or []
    fn_names = " ".join(f.get("name", "") for f in functions).lower()
    if any(h in fn_names or h in _strings_blob(revq).lower() for h in VM_HINTS):
        signals.append("vm-dispatch hint in functions/strings")
        return _result("rev", "rev-vm", 0.5, signals, capabilities)

    return _result("unknown", "unknown", 0.0, signals, capabilities)

def _result(track, subroute, confidence, signals, capabilities):
    return {
        "schema": "rat.route-result/v1",
        "track": track,
        "subroute": subroute,
        "confidence": confidence,
        "signals": signals,
        "capabilities": capabilities,
        "skill": subroute if subroute in SKILLS else None,
        "next": _next_hint(subroute),
    }

def _next_hint(subroute):
    return {
        "rev-checker": "revq --func <interesting-top>",
        "rev-vm": "solve/_template/rev/vmlift.py --disasm",
        "rev-packed": "gdbq / dynamic unpack trace before static re-analysis",
        "rev-symbolic": "solve/_template/rev/symsolve.py --find-str <success>",
        "pwn-stack": "pwncalc + pwnropcheck (no NX: shellcode path)",
        "pwn-format": "pwnleak on format-string output",
        "pwn-heap": "gdbq heap breakpoints + pwncrash",
        "pwn-rop": "pwnropcheck (NX on: ROP chain)",
        "pwn-kernel": "kernel/k_* tooling",
        "unknown": "revq/recon for more signal before routing",
    }.get(subroute, "revq/recon for more signal before routing")
