"""Project immutable bounded query results and active STATE evidence into Router v2."""
from __future__ import annotations

import json
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
    if not binary_digest or measured != binary_digest:
        raise ValueError("query result binary digest does not match the measured artifact")
    validate(doc, "rat.query-result/v1")
    stored = {key: value for key, value in doc.items() if key != "governor"}
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


def _valid_refutation(action, value):
    if (value.get("probe_id") != probe_id(value.get("binary_digest"), action)
            or value.get("coverage_complete") is not True
            or value.get("premise") not in action["resolves"]):
        return False
    if action["target"] == "inspect-bounded-input-callsite-then-measure-overwrite":
        sites = value.get("callsites")
        imports = set(action.get("candidate_imports") or [])
        return (isinstance(sites, list) and bool(sites)
                and bool(imports) and imports <= {"read", "fgets"}
                and imports <= {site.get("sink") for site in sites if isinstance(site, dict)}
                and all(isinstance(site, dict) and site.get("sink") in {"read", "fgets"}
                        and isinstance(site.get("destination_size"), int)
                        and isinstance(site.get("max_input_length"), int)
                        and 0 <= site["max_input_length"] <= site["destination_size"]
                        for site in sites))
    return value.get("conclusion") == "premise-refuted"


def load_feedback(state_dir, binary_digest, actions):
    """Read only matching, hash-checked results; invalidated observations fail closed."""
    stream = Stream(state_dir)
    events = stream.read()
    view = stream.view()
    notes = [e["payload"] for e in events if e["type"] == "note.recorded"
             and e["payload"].get("kind") == "route-query-result"]
    invalid = {oid for oid, obs in view.get("observations", {}).items()
               if obs.get("validity", {}).get("state") != "active"}
    results = {}
    for action in actions:
        pid = probe_id(binary_digest, action)
        query = ("func:" + action["target"] if action["query"] == "rat query func"
                 else "oracle" if action["query"] == "rat query oracle"
                 else "pwn" if action["query"] == "rat query pwn" else None)
        candidates = []
        for note in notes:
            if note.get("query") != query or note.get("binary_digest") != binary_digest:
                continue
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
                results[pid] = sorted(candidates, key=lambda c:(0 if c["status"] == "stale" else 1,
                                                                 c.get("artifact_digest", "")))[0]
    return results
