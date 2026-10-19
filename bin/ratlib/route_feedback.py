"""Project immutable bounded query results and active STATE evidence into Router v2."""
from __future__ import annotations

import json
import re
import uuid

from .artifact import get, put_bytes
from .route import probe_id
from .schema import validate
from .state_v2 import Stream, _classify_evidence


def record_query_result(state_dir, binary_digest, doc):
    """Persist the semantic query card, anchored to the measured binary.

    Governor advice is telemetry about prior actions, not a property of the
    query result. Keeping it out prevents repeated identical probes from
    minting fresh result artifacts when the governor first reports stuck.
    """
    # Never relabel an analysis result with the *current* file digest. The
    # binary can be replaced between analysis and persistence; laundering the
    # digest here would make stale facts resolve a new binary's probe.
    measured = (doc.get("provenance") or {}).get("binary_sha256")
    # revq emits a bare hex digest; the artifact/STATE contracts use sha256:hex.
    # Canonicalization is safe only after the actual measured bytes match.
    if isinstance(measured, str) and re.fullmatch(r"[0-9a-f]{64}", measured):
        measured = "sha256:" + measured
    if not binary_digest or measured != binary_digest:
        raise ValueError("query result binary digest does not match the measured artifact")
    validate(doc, "rat.query-result/v1")
    stored = {key: value for key, value in doc.items() if key != "governor"}
    stored["provenance"] = {**doc["provenance"], "binary_sha256": binary_digest}
    raw = json.dumps(stored, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    stream = Stream(state_dir)
    artifact = put_bytes(raw, root=stream.root, kind="query-result", media_type="application/json",
                         logical_name="rat-" + doc["query"].replace(":", "-") + ".json",
                         provenance={"binary_digest": binary_digest, "query": doc["query"]})
    digest = artifact["digest"]
    observation_id = "route-query-" + uuid.uuid4().hex
    stream.append("observation.recorded", {
        "observation_id": observation_id, "kind": "route.probe.query-result",
        "subject": {"binary_digest": binary_digest},
        "value": {"query": doc["query"], "artifact_digest": digest},
        "quality": {"level": "heuristic"}, "validity": {"state": "active"},
        "evidence": [digest],
    })
    stream.append("note.recorded", {
        "note_id": "query-result-" + digest[7:23], "kind": "route-query-result",
        "binary_digest": binary_digest, "query": doc["query"], "artifact_digest": digest,
        "observation_id": observation_id,
    })
    return digest


def record_followup_result(state_dir, binary_digest, query, doc):
    """Persist one tool-owned, hash-bound follow-up result as candidate evidence."""
    if query not in {"pwncrash", "decomp"} or not re.fullmatch(r"sha256:[0-9a-f]{64}", binary_digest):
        raise ValueError("invalid follow-up selector or binary digest")
    if doc.get("binary_digest") != binary_digest or doc.get("status") not in {"ok", "partial"}:
        raise ValueError("follow-up result has no matching measured binary")
    selector = doc.get("selector", "")
    if query == "decomp" and (not isinstance(selector, str) or not selector):
        raise ValueError("decomp result requires a function selector")
    stream = Stream(state_dir)
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    artifact = put_bytes(raw, root=stream.root, kind="route-followup-result",
                         media_type="application/json", logical_name=query + "-result.json",
                         provenance={"binary_digest": binary_digest, "query": query})
    digest = artifact["digest"]
    # Idempotence: decomp serves cached results on every lookup, so emit_file calls
    # this on a cache hit too.  If an identical active follow-up observation already
    # exists for this (binary, query, selector, content-addressed artifact), do not
    # append a duplicate observation/note -- the content is byte-identical (R-review #4).
    try:
        observations = stream.view().get("observations", {})
    except (OSError, ValueError):
        observations = {}
    for obs in observations.values():
        value = obs.get("value") or {}
        if (obs.get("kind") == "route.probe.followup-result"
                and (obs.get("validity") or {}).get("state") == "active"
                and obs.get("subject", {}).get("binary_digest") == binary_digest
                and value.get("query") == query
                and value.get("selector") == selector
                and value.get("artifact_digest") == digest):
            return digest  # already recorded; avoid STATE noise on repeated cache hits
    observation_id = "route-followup-" + uuid.uuid4().hex
    stream.append("observation.recorded", {
        "observation_id": observation_id, "kind": "route.probe.followup-result",
        "subject": {"binary_digest": binary_digest},
        "value": {"query": query, "selector": selector, "artifact_digest": digest},
        "quality": {"level": "heuristic"}, "validity": {"state": "active"},
        "evidence": [digest],
    })
    stream.append("note.recorded", {
        "note_id": "followup-result-" + digest[7:23], "kind": "route-followup-result",
        "binary_digest": binary_digest, "query": query, "selector": selector,
        "artifact_digest": digest, "observation_id": observation_id,
    })
    return digest


def _classify_query(action, doc):
    if doc.get("status") != "ok" or doc.get("coverage", {}).get("complete") is not True:
        return "partial", "query coverage is incomplete"
    if action["query"] == "rat query func":
        facts = doc.get("facts") or {}
        oracle = facts.get("oracle_candidates") or []
        kinds = {item.get("kind") for item in oracle if isinstance(item, dict)}
        if facts.get("compare_sites") and {"success", "failure"} <= kinds:
            return "resolved", "comparison sites and both oracle branches were recovered"
        return "partial", "complete function card does not establish comparison and both oracle branches"
    if action["query"] == "rat query oracle":
        facts = doc.get("facts") or {}
        if facts.get("success_candidate_count") and facts.get("failure_candidate_count"):
            return "resolved", "success and failure oracle candidates were recovered"
        return "partial", "success/failure oracle remains unbounded"
    # The PWN card contains imports and protections, not callsite or lifetime
    # evidence. Its complete output must never refute a vulnerability lead.
    return "partial", "query card does not establish the action's required premise"


def _classify_followup(action, doc, binary_digest):
    if doc.get("status") != "ok":
        return "partial", "follow-up probe did not complete"
    if action["query"] == "pwncrash":
        report = doc.get("report") or {}
        if not isinstance(report, dict):
            return "inspected", "crash probe report is not structured evidence"
        core = report.get("core") or {}
        measured_input = report.get("input") or {}
        measured_binary = report.get("binary") or {}
        if (not isinstance(core, dict) or not isinstance(measured_input, dict)
                or not isinstance(measured_binary, dict)):
            return "inspected", "crash probe report is not structured evidence"
        offset = core.get("control_cyclic_offset")
        length = measured_input.get("length")
        if (report.get("schema") == "rat.pwncrash/v1"
                and report.get("verdict") == "crash-reproduced"
                and measured_binary.get("sha256") == binary_digest
                and measured_input.get("kind") == "cyclic"
                and isinstance(offset, int) and not isinstance(offset, bool)
                and isinstance(length, int) and not isinstance(length, bool)
                and 0 <= offset < length):
            return "resolved", "cyclic return-address control candidate measured; primitive PASS still requires direct SELF proof"
        return "inspected", "crash probe completed without a measured control offset"
    return "inspected", "decompilation completed; attacker control or lifetime remains unverified"


def _valid_refutation(action, value):
    if (value.get("probe_id") != probe_id(value.get("binary_digest"), action)
            or value.get("coverage_complete") is not True
            or value.get("premise") not in action["resolves"]):
        return False
    if action["target"] == "inspect-bounded-input-callsite-then-measure-overwrite":
        # Import names do not enumerate callsites. A supplied list of safe
        # reads cannot rule out a second, omitted read in the same binary.
        # Keep this lead until a separate exhaustive callsite inventory can
        # bind every measured site to the binary.
        return False
    # A free-form conclusion plus an unrelated direct measurement is not a
    # deterministic refutation of heap, format, checker, or other premises.
    # Those families need their own bounded, machine-checkable validators.
    return False


def load_feedback(state_dir, binary_digest, actions):
    """Read only matching, hash-checked results; invalidated observations fail closed."""
    stream = Stream(state_dir)
    events = stream.read()
    # Use the same validated event snapshot for notes and observations. A
    # second Stream.read() can observe a different STATE revision mid-route.
    view = stream._materialize(events)
    notes_by_query = {}
    followups = []
    for event in events:
        if event["type"] != "note.recorded":
            continue
        note = event["payload"]
        if (note.get("kind") == "route-query-result"
                and note.get("binary_digest") == binary_digest):
            notes_by_query.setdefault(note.get("query"), []).append(note)
        if (note.get("kind") == "route-followup-result"
                and note.get("binary_digest") == binary_digest):
            followups.append(note)
    invalid = {oid for oid, obs in view.get("observations", {}).items()
               if obs.get("validity", {}).get("state") != "active"}
    results = {}
    for action in actions:
        pid = probe_id(binary_digest, action)
        query = ("func:" + action["target"] if action["query"] == "rat query func"
                 else "oracle" if action["query"] == "rat query oracle"
                 else "pwn" if action["query"] == "rat query pwn" else None)
        candidates = []
        for note in notes_by_query.get(query, ()):
            digest = note.get("artifact_digest")
            observation = view.get("observations", {}).get(note.get("observation_id"))
            if (not observation or observation.get("validity", {}).get("state") != "active"
                    or observation.get("subject", {}).get("binary_digest") != binary_digest
                    or digest not in (observation.get("evidence") or [])
                    or observation.get("value", {}).get("artifact_digest") != digest):
                candidates.append({"status": "stale", "reason": "query-result observation was invalidated or mismatched"})
                continue
            try:
                doc = json.loads(get(digest, root=stream.root))
                validate(doc, "rat.query-result/v1")
            except (OSError, ValueError, TypeError, KeyError, RuntimeError):
                candidates.append({"status": "stale", "reason": "query-result artifact is missing or invalid"})
                continue
            if (doc.get("query") != query or
                    doc.get("provenance", {}).get("binary_sha256") != binary_digest):
                candidates.append({"status": "stale", "reason": "query-result binary or selector does not match"})
                continue
            status, reason = _classify_query(action, doc)
            candidates.append({"status": status, "reason": reason, "artifact_digest": digest})
        if action["query"] in {"pwncrash", "decomp"}:
            for note in followups:
                if note.get("query") != action["query"]:
                    continue
                if action["query"] == "decomp" and note.get("selector") != action["target"].split(" ", 1)[-1]:
                    continue
                digest = note.get("artifact_digest")
                observation = view.get("observations", {}).get(note.get("observation_id"))
                if (not observation or observation.get("validity", {}).get("state") != "active"
                        or observation.get("subject", {}).get("binary_digest") != binary_digest
                        or digest not in (observation.get("evidence") or [])
                        or observation.get("value", {}).get("artifact_digest") != digest):
                    continue
                try:
                    doc = json.loads(get(digest, root=stream.root))
                except (OSError, ValueError, RuntimeError):
                    continue
                if (not isinstance(doc, dict) or
                        doc.get("binary_digest") != binary_digest or
                        doc.get("query") != action["query"] or
                        doc.get("selector", "") != note.get("selector")):
                    continue
                if doc.get("status") in {"ok", "partial"}:
                    status, reason = _classify_followup(action, doc, binary_digest)
                    candidates.append({"status": status, "reason": reason,
                                       "artifact_digest": digest, "observation_id": note.get("observation_id")})
        # Explicit refutations must be active, non-heuristic typed observations
        # of the exact probe and binary. They are never inferred from imports.
        for oid, obs in view.get("observations", {}).items():
            value = obs.get("value") or {}
            if (oid in invalid or obs.get("kind") != "route.probe.refutation"
                    or obs.get("quality", {}).get("level") not in {"derived", "direct"}
                    or obs.get("subject", {}).get("binary_digest") != binary_digest
                    or not isinstance(value, dict) or value.get("binary_digest") != binary_digest
                    or not _valid_refutation(action, value)
                    or not obs.get("evidence")):
                continue
            try:
                for digest in obs["evidence"]:
                    envelope = json.loads(get(digest, root=stream.root))
                    classification = _classify_evidence(digest, stream.root)
                    measured = classification.get("subject_digest")
                    if classification["level"] == "derived":
                        binding = (envelope.get("extensions") or {}).get("subject_binding") or {}
                        if (binding.get("role") != "binary" or
                                not any(item.get("role") == "binary" and item.get("digest") == binding.get("digest")
                                        for item in envelope.get("inputs", []))):
                            raise ValueError("refutation evidence has no binary binding")
                        measured = binding.get("digest")
                    if measured != binary_digest:
                        raise ValueError("refutation evidence measures another binary")
            except (OSError, ValueError, RuntimeError):
                continue
            candidates.append({"status": "refuted", "reason": value.get("reason", "bounded refutation"),
                               "observation_id": oid})
        if candidates:
            # Conclusive evidence dominates partial cards; contradictory
            # conclusive outcomes remain stale until inspected by an operator.
            conclusive = [c for c in candidates if c["status"] in {"resolved", "refuted"}]
            states = {c["status"] for c in conclusive}
            if len(states) > 1:
                results[pid] = {"status": "stale", "reason": "conflicting probe evidence"}
            elif conclusive:
                results[pid] = sorted(conclusive, key=lambda c:(c["status"], c.get("artifact_digest", ""), c.get("observation_id", "")))[0]
            else:
                results[pid] = sorted(candidates, key=lambda c:(0 if c["status"] == "inspected" else 1 if c["status"] == "stale" else 2,
                                                                 c.get("artifact_digest", "")))[0]
    return results
