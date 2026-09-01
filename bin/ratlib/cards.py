"""Bounded analysis-card projections built from existing deterministic artifacts.

This module does not analyze binaries and does not mint new evidence.  It only
projects already-computed profile/route facts into small model-facing working
sets.  Runtime primitive truth remains owned by STATE v2 + deterministic
verification; import presence is never promoted into a PASS primitive here.
"""
from __future__ import annotations

from collections.abc import Mapping

from .route import (
    FORMAT_IMPORTS,
    HEAP_IMPORTS,
    INPUT_IMPORTS,
    KERNEL_IMPORTS,
    STRONG_OVERFLOW_IMPORTS,
    WEAK_OVERFLOW_IMPORTS,
    route as route_fn,
)

PROTECTION_FACTS = ("elf.nx", "elf.pie", "elf.canary", "elf.relro")
COMMAND_IMPORTS = {"system", "execve", "popen"}


def _fact_map(profile):
    out = {}
    for fact in (profile or {}).get("facts", []) or []:
        if isinstance(fact, Mapping) and isinstance(fact.get("kind"), str):
            out[fact["kind"]] = fact.get("value")
    return out


def _binary_digest(profile):
    for item in (profile or {}).get("inputs", []) or []:
        if isinstance(item, Mapping) and item.get("role") == "binary" and item.get("digest"):
            return item["digest"]
    for key in ("binary_sha256", "sha256"):
        value = (profile or {}).get(key)
        if isinstance(value, str) and value:
            return value if value.startswith("sha256:") else "sha256:" + value
    return None


def project_pwn_capability(profile):
    """Return a deterministic, bounded-ready PWN capability projection.

    Facts are restricted to binary-profile observations: protection properties,
    import-derived sink groups, and exact counts.  Route selection is explicitly
    heuristic because the presence of an API does not prove vulnerable use at a
    callsite.  The result intentionally contains no ``verified_primitive`` field;
    verified primitive lifecycle is canonical in STATE v2 and must not be
    duplicated by a static projection.
    """
    if not isinstance(profile, Mapping):
        raise TypeError("profile must be a mapping")

    imports = {x for x in (profile.get("imports", []) or []) if isinstance(x, str)}
    facts = _fact_map(profile)
    protections = {kind: facts[kind] for kind in PROTECTION_FACTS if kind in facts}
    sinks = {
        "overflow_unbounded": sorted(imports & STRONG_OVERFLOW_IMPORTS),
        "overflow_bounded": sorted(imports & WEAK_OVERFLOW_IMPORTS),
        "format": sorted(imports & FORMAT_IMPORTS),
        "heap": sorted(imports & HEAP_IMPORTS),
        "kernel": sorted(imports & KERNEL_IMPORTS),
        "input": sorted(imports & INPUT_IMPORTS),
        "command_exec": sorted(imports & COMMAND_IMPORTS),
    }
    sink_counts = {kind: len(values) for kind, values in sinks.items()}

    routed = route_fn(profile=profile)
    candidate_routes = []
    if routed.get("track") == "pwn":
        candidate_routes.append({
            "track": "pwn",
            "subroute": routed.get("subroute"),
            "confidence": routed.get("confidence"),
            "primary": True,
        })
    for alt in routed.get("alternatives", []) or []:
        if isinstance(alt, Mapping) and alt.get("track") == "pwn":
            candidate_routes.append({
                "track": "pwn",
                "subroute": alt.get("subroute"),
                "confidence": alt.get("confidence"),
                "primary": False,
            })

    limitations = [
        "import presence identifies attention targets; it does not prove unsafe callsite arguments",
        "static profile data does not prove RIP/PC control, arbitrary read/write, leak stability, heap overlap, or kernel object reuse",
        "verified primitive PASS remains canonical in STATE v2 and requires deterministic direct evidence",
    ]
    subroutes = {item.get("subroute") for item in candidate_routes}
    if "pwn-rop" in subroutes:
        limitations.append("ROP gadget/register-loading capability is unresolved until pwnropcheck or equivalent deterministic inventory")
    if "pwn-format" in subroutes:
        limitations.append("format argument offset and read/write reachability are unresolved until measured")
    if "pwn-heap" in subroutes:
        limitations.append("allocator lifetime, reuse, overlap, and safe-linking constraints are unresolved until measured")
    if "pwn-kernel" in subroutes:
        limitations.append("device/ioctl surface and object lifetime are unresolved until measured")

    return {
        "kind": "pwn-capability",
        "facts": {
            "protections": protections,
            "sinks": sinks,
            "sink_counts": sink_counts,
            "imports_total": len(imports),
        },
        "heuristics": {
            "candidate_routes": candidate_routes,
            "signals": list(routed.get("signals", []) or []),
            "next": list(routed.get("next", []) or []),
            "limitations": limitations,
        },
        "provenance": {
            "binary_sha256": _binary_digest(profile),
            "profile_schema": profile.get("schema"),
        },
    }
