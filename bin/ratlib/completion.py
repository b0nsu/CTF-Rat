"""Canonical verified-solve gate shared by benchmark/runtime consumers.

A primitive PASS proves a measured primitive.  It is not, by itself, a solved
challenge.  A verified solve additionally requires an active, non-stale
rat-verify PASS linked to the same primitive and completed exploit task.
"""
from __future__ import annotations

import re
import hashlib
import json

from .orchestration import GateError, _task, _verification_report
from .state_v2 import Stream, trusted_producer_for_build


_ENGINE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

# Primitive classes are an independent signal because older/early STATE may not
# contain a route assessment yet. Keep this list narrow: it names claims whose
# result is reconstructed from a checker/oracle, not ordinary exploitation
# primitives such as control-flow or memory corruption.
_SYMBOLIC_PRIMITIVE_CLASSES = {
    "solution-reconstruction",
    "symbolic-reconstruction",
    "flag-reconstruction",
    "secret-reconstruction",
    "key-reconstruction",
}
_REV_ROUTE_LEADS = {"checker", "vm", "oracle-discovery"}
_REV_PROGRAM_SHAPES = {"checker", "vm-candidate", "oracle-needed"}
_PWN_ROUTE_LEADS = {"stack-overwrite", "format-string", "heap-lifetime", "kernel"}
_PWN_DIMENSIONS = {
    "stack-overwrite-candidate", "format-string-candidate",
    "heap-lifetime-candidate", "kernel-candidate",
}


def _rev_route_assessment(note):
    """Classify only clear rev-only route evidence; Router v2 leads can coexist."""
    explicit_track = note.get("challenge_track", note.get("track"))
    if isinstance(explicit_track, str):
        normalized_track = explicit_track.strip().lower().replace("_", "-")
        if normalized_track in {"rev", "reverse-engineering", "reverse engineering"}:
            return True
        if normalized_track in {"pwn", "binary-exploitation"}:
            return False

    leads = ({item for item in note.get("leads", []) if isinstance(item, str)}
             if isinstance(note.get("leads"), list) else set())
    dimensions = note.get("dimensions", {})
    if not isinstance(dimensions, dict):
        dimensions = {}
    program_shapes = dimensions.get("program_shapes", [])
    vulnerability_surfaces = dimensions.get("vulnerability_surfaces", [])
    if not isinstance(program_shapes, list):
        program_shapes = []
    if not isinstance(vulnerability_surfaces, list):
        vulnerability_surfaces = []

    program_shapes = {item for item in program_shapes if isinstance(item, str)}
    vulnerability_surfaces = {item for item in vulnerability_surfaces if isinstance(item, str)}
    has_rev_evidence = bool(leads & _REV_ROUTE_LEADS or program_shapes & _REV_PROGRAM_SHAPES)
    has_pwn_evidence = bool(
        leads & _PWN_ROUTE_LEADS
        or vulnerability_surfaces & _PWN_DIMENSIONS
        or program_shapes & _PWN_DIMENSIONS
    )
    return has_rev_evidence and not has_pwn_evidence


def _is_rev_track(view):
    """Keep rev route evidence across later, potentially weaker assessments.

    A later note cannot erase a previously recorded rev lead. Router assessments
    are provisional, so the caller must also consider direct pwn evidence.
    """
    notes = view.get("notes", [])
    if not isinstance(notes, list):
        return False
    return any(
        _rev_route_assessment(note)
        for note in notes
        if isinstance(note, dict)
        and note.get("kind") in {"route-assessment", "challenge-track"}
    )


def _has_direct_pwn_evidence(primitive, view):
    """A measured pwn observation outweighs a provisional static rev lead."""
    observations = view.get("observations", {})
    if not isinstance(observations, dict):
        return False
    for observation_id in primitive.get("self_evidence", []):
        observation = observations.get(observation_id, {})
        if not isinstance(observation, dict):
            continue
        kind = observation.get("kind")
        if (isinstance(kind, str) and kind.startswith("pwn.")
                and observation.get("quality", {}).get("level") == "direct"
                and observation.get("validity", {}).get("state") == "active"):
            return True
    return False


def _symbolic_engine_issue(primitive, view):
    """Validate sanctioned provenance for symbolic/rev completion claims.

    ``solve_origin`` is useful metadata, but it is agent-authored and therefore
    cannot decide whether the gate runs. Route evidence and symbolic-recovery
    primitive classes independently activate the default-deny check.
    """
    extensions = primitive.get("extensions", {})
    if not isinstance(extensions, dict):
        extensions = {}
    primitive_class = primitive.get("class", "")
    if not isinstance(primitive_class, str):
        primitive_class = ""
    symbolic_claim = (
        extensions.get("solve_origin") == "rev-symbolic"
        or primitive_class.strip().lower().replace("_", "-") in _SYMBOLIC_PRIMITIVE_CLASSES
        or (_is_rev_track(view) and not _has_direct_pwn_evidence(primitive, view))
    )
    if not symbolic_claim:
        return None
    observation_id = extensions.get("engine_observation_id")
    observations = view.get("observations", {})
    observation = observations.get(observation_id, {}) if isinstance(observations, dict) else {}
    if not isinstance(observation, dict):
        observation = {}
    producer = observation.get("producer", {})
    value = observation.get("value", {})
    subject = observation.get("subject", {})
    if not isinstance(producer, dict):
        producer = {}
    if not isinstance(value, dict):
        value = {}
    if not isinstance(subject, dict):
        subject = {}
    build_digest = producer.get("engine_build_digest")
    identity = producer.get("engine_identity")
    identity_ok = False
    if isinstance(identity, dict) and set(identity) == {"harness_sha256", "packages", "python", "engine"}:
        harness_digest = identity.get("harness_sha256")
        packages = identity.get("packages")
        if (isinstance(harness_digest, str) and _ENGINE_DIGEST.fullmatch(harness_digest)
                and trusted_producer_for_build(harness_digest) == "symsolve.py"
                and isinstance(packages, dict) and set(packages) == {"angr", "unicorn"}
                and all(value is None or isinstance(value, str) for value in packages.values())
                and isinstance(identity.get("python"), str)
                and identity.get("engine") == "native-unicorn"):
            encoded_identity = {**identity, "harness_sha256": harness_digest.removeprefix("sha256:")}
            encoded = json.dumps(encoded_identity, sort_keys=True, separators=(",", ":")).encode()
            identity_ok = build_digest == "sha256:" + hashlib.sha256(encoded).hexdigest()
    if (observation.get("kind") == "rev.symsolve.concrete-verify"
            and observation.get("validity", {}).get("state") == "active"
            and observation.get("quality", {}).get("level") == "heuristic"
            and observation.get("observation_id") == observation_id
            and subject.get("sha256") == primitive.get("input_digest")
            and value.get("verdict") == "pass"
            and producer.get("engine") == "symsolve"
            and value.get("engine") == "symsolve"
            and value.get("engine_build_digest") == build_digest
            and isinstance(build_digest, str)
            and _ENGINE_DIGEST.fullmatch(build_digest)
            and identity_ok):
        return None
    return "unsanctioned-symbolic-engine"


def _operator_attested(primitive, record, report_digest, view, root=None):
    """Validate an embedded operator attestation against evidence in this solve."""
    extensions = primitive.get("extensions", {})
    attestation = extensions.get("operator_attestation") if isinstance(extensions, dict) else None
    if not isinstance(attestation, dict):
        return False
    available = {report_digest}
    observation_ids = []
    for values in (primitive.get("self_evidence", []), record.get("evidence_ids", [])):
        if isinstance(values, list):
            observation_ids.extend(item for item in values if isinstance(item, str))
    for observation_id in observation_ids:
        observation = view.get("observations", {}).get(observation_id, {})
        if not isinstance(observation, dict) or observation.get("validity", {}).get("state") != "active":
            continue
        for item in observation.get("evidence", []):
            if not isinstance(item, str):
                continue
            if root is not None:
                try:
                    from .artifact import get
                    get(item, root=root)
                except (OSError, RuntimeError, ValueError):
                    continue
            available.add(item)
    try:
        from .writeup_contract import validate_attestation
        validate_attestation(attestation, available)
    except (ImportError, ValueError, TypeError):
        return False
    return True


def completion_gate(root, verification_id=None):
    """Return the authoritative local completion decision for ``root``.

    The gate deliberately re-reads immutable verification artifacts instead of
    trusting the mutable/event projection alone.  ``verification.recorded`` is
    accepted only when its rat-verify report still authenticates, its primitive
    remains active (PASS or consumed), and its exploit task is still a completed
    P4 exploit-builder task bound to that primitive/input/environment.
    """
    try:
        stream = Stream(root)
        events = stream.read()
        # Canonical Stream can materialize the already-validated snapshot without
        # a second full read. Minimal Stream-compatible adapters used by callers/tests
        # may expose only read()+view(); preserve that compatibility path.
        view = stream._materialize(events) if hasattr(stream, "_materialize") else stream.view()
    except (OSError, ValueError) as exc:
        return {"verified": False, "reason": "state-invalid", "detail": str(exc)}

    active = {
        pid: primitive
        for pid, primitive in view.get("primitives", {}).items()
        if primitive.get("status") in {"pass", "consumed"}
    }
    if not active:
        return {"verified": False, "reason": "no-active-primitive"}

    stale = {
        e.get("payload", {}).get("verification_id")
        for e in events
        if e.get("type") == "verification.staled"
    }
    records = [
        e.get("payload", {})
        for e in events
        if e.get("type") == "verification.recorded"
        and e.get("payload", {}).get("verification_id") not in stale
    ]

    for record in reversed(records):
        if verification_id is not None and record.get("verification_id") != verification_id:
            continue
        if record.get("verdict") != "pass" or record.get("environment_match") is not True:
            continue
        primitive_id = record.get("primitive_id")
        primitive = active.get(primitive_id)
        if primitive is None:
            continue
        if record.get("primitive_revision") is not None:
            if record["primitive_revision"] != primitive.get("revision"):
                continue
        else:
            # Historical records lack a revision field. A later revision must
            # never inherit an earlier verifier verdict.
            verification_seq = next((e.get("seq", 0) for e in events
                                     if e.get("type") == "verification.recorded"
                                     and e.get("payload", {}).get("verification_id") == record.get("verification_id")), 0)
            if any(e.get("type") == "primitive.revised"
                   and e.get("payload", {}).get("primitive_id") == primitive_id
                   and e.get("seq", 0) > verification_seq for e in events):
                continue
        report_digest = record.get("report_digest")
        try:
            report = _verification_report(root, report_digest)
        except (GateError, OSError, ValueError):
            continue
        provenance = report.get("provenance", {})
        producer = report.get("producer", {})
        if report.get("verdict") != "pass" or report.get("environment_match") is not True:
            continue
        if provenance.get("primitive_id") != primitive_id:
            continue
        if provenance.get("exploit_task_id") != record.get("exploit_task_id"):
            continue
        if provenance.get("environment_digest") != primitive.get("environment_digest"):
            continue
        if producer.get("build_digest") != record.get("producer_build_digest"):
            continue
        try:
            task, _ = _task(root, provenance.get("exploit_task_id"))
        except GateError:
            continue
        if (task.get("phase") != "solve-P4" or task.get("role") != "exploit-builder"
                or task.get("status") != "completed"):
            continue
        if task.get("primitive_id") != primitive_id:
            continue
        if task.get("input_digest") != primitive.get("input_digest"):
            continue
        if task.get("environment_digest") != primitive.get("environment_digest"):
            continue
        engine_issue = _symbolic_engine_issue(primitive, view)
        operator_attested = _operator_attested(primitive, record, report_digest, view, root)
        if engine_issue and not operator_attested:
            return {
                "verified": False,
                "reason": engine_issue,
                "primitive_id": primitive_id,
                "verification_id": record.get("verification_id"),
                "report_digest": report_digest,
                "exploit_task_id": provenance.get("exploit_task_id"),
            }
        result = {
            "verified": True,
            "reason": "verified",
            "primitive_id": primitive_id,
            "verification_id": record.get("verification_id"),
            "report_digest": report_digest,
            "exploit_task_id": provenance.get("exploit_task_id"),
        }
        if operator_attested:
            result["operator_attested"] = True
        return result

    return {"verified": False, "reason": "no-active-verification"}


def verified_solve(root):
    """Boolean convenience wrapper for consumers that only need the verdict."""
    return completion_gate(root).get("verified") is True
