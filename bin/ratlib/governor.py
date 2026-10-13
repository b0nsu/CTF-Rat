"""Progress Novelty Governor.

Time-based "stuck" detection is replaced by a novelty check: if the last
`window` tool/query actions produced no new artifact digest, finding
revision, ruled-out route, or primitive status change, recommend a re-route
or DEEP escalation instead of continuing to retry.

The rat dispatcher persists the rolling novelty flags. This module only
normalizes STATE evidence and returns advice; it executes no probe.
"""
from __future__ import annotations
import hashlib
import json

DEFAULT_WINDOW = 5


def evidence_snapshot(events):
    """Canonical solving evidence, excluding notes, timestamps and duplicate writes."""
    observations, findings, primitives, ruled_out, invalidated = {}, {}, {}, {}, set()
    for event in events:
        kind, p = event.get("type"), event.get("payload") or {}
        if kind == "observation.recorded":
            key = p.get("observation_id")
            if key:
                observations[key] = {"evidence": sorted(set(p.get("evidence") or [])),
                                     "kind": p.get("kind"), "value": p.get("value")}
        elif kind == "finding.revised":
            key = p.get("finding_id")
            if key:
                findings[key] = {"state": p.get("state"),
                                 "class": p.get("class"),
                                 "evidence": sorted(set(p.get("evidence_observation_ids") or [])),
                                 "contradictions": p.get("contradictions") or []}
        elif kind == "primitive.revised":
            key = p.get("primitive_id")
            if key:
                primitives[key] = {"status": p.get("status"),
                                   "evidence": sorted(set(p.get("self_evidence") or [])),
                                   "input_digest": p.get("input_digest"),
                                   "environment_digest": p.get("environment_digest")}
        elif kind == "primitive.consumed":
            primitive = primitives.get(p.get("primitive_id"))
            if (primitive and primitive["status"] == "pass"
                    and primitive["input_digest"] == p.get("input_digest")
                    and primitive["environment_digest"] == p.get("environment_digest")):
                primitive["status"] = "consumed"
        elif kind == "route.ruled_out" and p.get("fingerprint"):
            ruled_out[p["fingerprint"]] = sorted(set(p.get("evidence_observation_ids") or []))
        elif kind == "evidence.invalidated":
            invalidated.update(p.get("observation_ids") or [])
    # Re-recording identical evidence under a new observation ID is not progress.
    for finding in findings.values():
        if set(finding["evidence"]) & invalidated and finding["state"] not in {"refuted", "invalidated"}:
            finding["state"] = "invalidated" if finding["state"] == "confirmed" else "stale"
    for primitive in primitives.values():
        if set(primitive["evidence"]) & invalidated and primitive["status"] != "fail":
            primitive["status"] = "stale"
    unique_observations = sorted({json.dumps(x, sort_keys=True, ensure_ascii=False, default=str)
                                  for x in observations.values()})
    return {"observations": unique_observations, "findings": findings,
            "primitives": primitives, "ruled_out": ruled_out,
            "invalidated": sorted(invalidated)}


def snapshot_digest(events):
    raw = json.dumps(evidence_snapshot(events), sort_keys=True, ensure_ascii=False, default=str).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def recommend(events, fallback="re-route-or-deep-escalate"):
    """Evidence-linked advice; never an executable command."""
    state = evidence_snapshot(events)
    # Stream validation and typed SELF PASS remain authoritative. For advice,
    # use explicit observation quality/validity when present. Legacy synthetic
    # events without this metadata retain A1 advisory compatibility.
    observations = {p["observation_id"]: p for e in events
                    if e.get("type") == "observation.recorded"
                    for p in [e.get("payload") or {}] if p.get("observation_id")}
    observed_ids = set(observations) - set(state["invalidated"])
    observed_ids = {oid for oid in observed_ids
                    if (observations[oid].get("validity") or {}).get("state", "active") == "active"}
    direct_ids = {oid for oid in observed_ids
                  if (observations[oid].get("quality") or {}).get("level", "direct") == "direct"}

    # A stale environment can invalidate a chain; check it before continuing.
    # Invalidated observations can justify an environment recheck, but an
    # observation ID which was never recorded cannot.
    for key, p in sorted(state["findings"].items()):
        if (p["class"] in {"env", "environment"}
                and p["state"] in {"stale", "invalidated"}
                and any(x in observations for x in p["evidence"])):
            return {"action": "verify-environment", "basis": ["finding:" + key]}

    # An active, direct-evidence-linked PASS is more actionable than a
    # general unknown. A refuted finding citing the *same active observation*
    # is a conflicting premise, however: recommend a re-route before reuse.
    # Shared evidence is a conservative conflict signal, NOT proof of semantic
    # dependency. There is no typed unknown->primitive dependency contract.
    for key, p in sorted(state["primitives"].items()):
        if (p["status"] in {"pass", "consumed"} and p["evidence"]
                and all(x in direct_ids for x in p["evidence"])):
            for finding_id, finding in sorted(state["findings"].items()):
                if (finding["state"] in {"refuted", "invalidated"}
                        and set(finding["evidence"]) & set(p["evidence"]) & observed_ids):
                    return {"action": "re-route", "basis": ["finding:" + finding_id,
                                                               "primitive:" + key]}
            return {"action": "focused-deep", "basis": ["primitive:" + key]}

    # Refutations should not be masked by a prior, unrelated unknown.
    for key, p in sorted(state["findings"].items()):
        if p["state"] in {"refuted", "invalidated"} and p["evidence"]:
            return {"action": "re-route", "basis": ["finding:" + key]}
    for fingerprint, evidence in sorted(state["ruled_out"].items()):
        if evidence and all(x in observed_ids for x in evidence):
            return {"action": "re-route", "basis": ["route:" + fingerprint] +
                    ["observation:" + x for x in evidence]}

    # Evidence-linked unknowns still warrant a bounded discriminator when
    # no stronger continuation or invalidation signal remains.
    for event in reversed(events):
        if event.get("type") != "unknown.recorded":
            continue
        p = event.get("payload") or {}
        evidence = p.get("evidence_observation_ids") or []
        if evidence and all(x in observed_ids for x in evidence):
            return {"action": "low-cost-discriminator", "basis": ["observation:" + x for x in evidence]}
    return {"action": fallback, "basis": []}

def check_progress(recent_novelty_flags, *, window=DEFAULT_WINDOW):
    """`recent_novelty_flags` is a chronological list of bool: whether each of
    the caller's last tool/query actions introduced something new (new
    artifact digest, finding revision, ruled-out route, or primitive status
    change) relative to everything already seen. Fewer than `window` actions
    recorded so far is not yet "stuck" -- there isn't enough history."""
    tail = list(recent_novelty_flags)[-window:]
    if len(tail) < window:
        return {"stuck": False, "action": None, "reason": None}
    if any(tail):
        return {"stuck": False, "action": None, "reason": None}
    return {
        "stuck": True,
        "action": "re-route-or-deep-escalate",
        "reason": "no new artifact digest / finding revision / ruled-out route / "
                  "primitive status change in the last %d actions" % window,
    }
