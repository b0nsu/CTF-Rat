"""Bounded analysis-card projections built from existing deterministic artifacts.

This module does not analyze binaries and does not mint new evidence.  It only
projects already-computed profile/route facts into small model-facing working
sets.  Runtime primitive truth remains owned by STATE v2 + deterministic
verification; import presence is never promoted into a PASS primitive here.
"""
from __future__ import annotations

from collections.abc import Mapping

from .route import (
    FORMAT as FORMAT_IMPORTS, HEAP as HEAP_IMPORTS, INPUT as INPUT_IMPORTS,
    KERNEL as KERNEL_IMPORTS, STRONG as STRONG_OVERFLOW_IMPORTS,
    OVERFLOW,
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


def _canonical_imports(profile):
    """Canonicalize deterministic ELF import names without changing evidence grade.

    ``readelf -sW`` can expose a dynamic symbol as ``read@GLIBC_2.2.5`` (or
    ``foo@@VER``). Route/capability vocabularies intentionally use stable API
    names, so strip only the ELF symbol-version suffix. Do not perform fuzzy
    matching or aliases here: the resulting base name still comes directly from
    the profile's imported-symbol fact.
    """
    out = set()
    for value in (profile.get("imports", []) or []):
        if not isinstance(value, str) or not value:
            continue
        out.add(value.split("@", 1)[0])
    return out


def _discriminating_next(leads):
    """Choose one bounded *post-capability* probe, never another PWN card.

    `rat route` intentionally points provisional PWN classifications at
    ``rat query pwn`` first so the model sees one compact static capability
    projection.  Once inside that card, repeating the same query would be a
    no-information loop.  Advance to the cheapest existing tool that can test
    the primary candidate's missing premise instead.  These are experiment
    suggestions, not proof and not automatic execution.
    """
    probes = {
        "pwn-stack": {"query": "pwncrash", "target": "reproduce-overwrite-and-measure-control-offset"},
        "pwn-rop": {"query": "pwncrash", "target": "prove-PC-control-before-ROP-gadget-inventory"},
        "pwn-format": {"query": "decomp", "target": "printf-family-callsite: prove-format-argument-user-control"},
        "pwn-heap": {"query": "decomp", "target": "allocator/menu-callsite: map-object-lifetime-before-heap-technique"},
        "pwn-kernel": {"query": "decomp", "target": "confirm-kernel-module-and-copy-user-callsite-before-kernel-tooling"},
    }
    # A candidate is an inspection lead, not an exclusive diagnosis. Surface
    # distinct inexpensive experiments; the agent picks based on live evidence.
    next_queries = []
    for item in leads:
        probe = probes.get(item)
        if probe and probe not in next_queries:
            next_queries.append(probe)
    return next_queries[:3]


def project_pwn_capability(profile):
    """Return a deterministic, bounded-ready PWN capability projection.

    Facts are restricted to binary-profile observations: protection properties,
    import-derived sink groups, and exact counts. Route selection is explicitly
    heuristic because the presence of an API does not prove vulnerable use at a
    callsite. The result intentionally contains no ``verified_primitive`` field;
    verified primitive lifecycle is canonical in STATE v2 and must not be
    duplicated by a static projection.
    """
    if not isinstance(profile, Mapping):
        raise TypeError("profile must be a mapping")

    imports = _canonical_imports(profile)
    facts = _fact_map(profile)
    protections = {kind: facts[kind] for kind in PROTECTION_FACTS if kind in facts}
    sinks = {
        "overflow_unbounded": sorted(imports & STRONG_OVERFLOW_IMPORTS),
        "overflow_bounded": sorted(imports & (OVERFLOW - STRONG_OVERFLOW_IMPORTS)),
        "format": sorted(imports & FORMAT_IMPORTS),
        "heap": sorted(imports & HEAP_IMPORTS),
        "kernel": sorted(imports & KERNEL_IMPORTS),
        "input": sorted(imports & INPUT_IMPORTS),
        "command_exec": sorted(imports & COMMAND_IMPORTS),
    }
    sink_counts = {kind: len(values) for kind, values in sinks.items()}

    # Do not call route() again on a profile-only subset. The main route
    # consumed profile + REV evidence; re-running it here can fabricate a
    # different "primary". Reuse only the router's existing import vocabulary
    # to enumerate independent attention leads, without selecting a winner.
    labels = []
    if imports & HEAP_IMPORTS: labels.append("pwn-heap")
    if imports & FORMAT_IMPORTS and imports & INPUT_IMPORTS: labels.append("pwn-format")
    if imports & OVERFLOW: labels.append("pwn-rop" if facts.get("elf.nx") is True else "pwn-stack")
    if imports & KERNEL_IMPORTS:
        labels.append("pwn-kernel")
    leads = sorted(set(labels))

    limitations = [
        "import presence identifies attention targets; it does not prove unsafe callsite arguments",
        "static profile data does not prove RIP/PC control, arbitrary read/write, leak stability, heap overlap, or kernel object reuse",
        "verified primitive PASS remains canonical in STATE v2 and requires deterministic direct evidence",
    ]
    subroutes = set(leads)
    if "pwn-rop" in subroutes:
        limitations.append("ROP gadget/register-loading capability is unresolved until PC control is measured and pwnropcheck inventory is justified")
    if "pwn-format" in subroutes:
        limitations.append("format argument control, offset, and read/write reachability are unresolved until measured")
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
            "leads": leads,
            "signals": [],
            "next": _discriminating_next(leads),
            "limitations": limitations,
        },
        "provenance": {
            "binary_sha256": _binary_digest(profile),
            "profile_schema": profile.get("schema"),
        },
    }
