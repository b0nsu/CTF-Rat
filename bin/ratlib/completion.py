"""Canonical verified-solve gate shared by benchmark/runtime consumers.

A primitive PASS proves a measured primitive.  It is not, by itself, a solved
challenge.  A verified solve additionally requires an active, non-stale
rat-verify PASS linked to the same primitive and completed exploit task.
"""
from __future__ import annotations

from .orchestration import GateError, _task, _verification_report
from .state_v2 import Stream


def completion_gate(root):
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
        view = stream.view()
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
        if record.get("verdict") != "pass" or record.get("environment_match") is not True:
            continue
        primitive_id = record.get("primitive_id")
        primitive = active.get(primitive_id)
        if primitive is None:
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
        return {
            "verified": True,
            "reason": "verified",
            "primitive_id": primitive_id,
            "verification_id": record.get("verification_id"),
            "report_digest": report_digest,
            "exploit_task_id": provenance.get("exploit_task_id"),
        }

    return {"verified": False, "reason": "no-active-verification"}


def verified_solve(root):
    """Boolean convenience wrapper for consumers that only need the verdict."""
    return completion_gate(root).get("verified") is True
