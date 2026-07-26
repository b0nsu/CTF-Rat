"""Materialize trusted observations from broker-produced artifact occurrences."""
from __future__ import annotations
import json, os, uuid

from .artifact import get, metadata, put_bytes
from .orchestration import GateError, _active_attempt, _lineage, _state
from .receipt import verify as verify_receipt
from .state_v2 import Stream

# Directness is a producer policy.  Callers may describe the subject/value but
# never select the evidence quality.
DIRECT_TOOLS={"rat-verify","rat-dyn","gdbq","rat-qiling"}

def materialize(root, *, receipt_digest, artifact_digest, subject, kind, value):
    root=os.path.abspath(root); store=os.path.join(root,".rat")
    if not all(isinstance(x,str) and x for x in (receipt_digest,artifact_digest,subject,kind)):
        raise GateError("receipt, artifact, subject, and kind are required")
    try:
        receipt=json.loads(get(receipt_digest,root=store)); receipt_meta=metadata(receipt_digest,root=store)
    except Exception as exc: raise GateError("broker receipt is missing or corrupt") from exc
    if receipt_meta.get("kind")!="broker-receipt" or receipt_meta.get("provenance",{}).get("broker") is not True:
        raise GateError("receipt was not written by the broker")
    required={"schema","receipt_id","task_id","checkpoint_id","phase_attempt_id","lineage_id","lease_id","tool","inputs","sandbox","result","signature"}
    if set(receipt)!=required or receipt.get("schema")!="rat.broker-receipt/v1": raise GateError("invalid broker receipt schema")
    if not verify_receipt(store,receipt): raise GateError("broker receipt signature is invalid")
    try:
        with open(os.path.join(store,"tasks",receipt["task_id"]+".json"),encoding="utf-8") as source: task=json.load(source)
    except (OSError,ValueError) as exc: raise GateError("receipt task is missing") from exc
    if (task.get("checkpoint_id"),task.get("phase_attempt_id"),task.get("lineage_id")) != (receipt["checkpoint_id"],receipt["phase_attempt_id"],receipt["lineage_id"]):
        raise GateError("receipt does not match durable task provenance")
    if task.get("status") not in {"running","completed"} or _state(root)!=task.get("phase") or _active_attempt(root,task["phase"])!=task.get("phase_attempt_id") or _lineage(root)!=task.get("lineage_id"):
        raise GateError("receipt task is stale or no longer active")
    artifacts=receipt.get("result",{}).get("artifacts",[])
    if artifact_digest not in {x.get("digest") for x in artifacts if isinstance(x,dict)}: raise GateError("artifact was not produced by this broker receipt")
    try: content_meta=metadata(artifact_digest,root=store)
    except Exception as exc: raise GateError("receipt artifact is missing or corrupt") from exc
    level="direct" if receipt.get("tool",{}).get("name") in DIRECT_TOOLS else "derived"
    occurrence={"schema":"rat.evidence-occurrence/v1","occurrence_id":"occ_"+uuid.uuid4().hex,"content_digest":artifact_digest,"receipt_digest":receipt_digest,"task_id":task["task_id"],"checkpoint_id":task["checkpoint_id"],"phase_attempt_id":task["phase_attempt_id"],"lineage_id":task["lineage_id"],"tool":receipt["tool"],"artifact_kind":content_meta.get("kind"),"quality_level":level}
    occurrence_artifact=put_bytes(json.dumps(occurrence,sort_keys=True,separators=(",",":")).encode(),kind="evidence-occurrence",media_type="application/json",logical_name=occurrence["occurrence_id"]+".json",root=store,provenance={"evidence_policy":{"level":level,"promotion_allowed":level=="direct"},"receipt_digest":receipt_digest,"content_digest":artifact_digest})
    observation={"observation_id":"obs_"+uuid.uuid4().hex,"occurrence_id":occurrence["occurrence_id"],"quality":{"level":level},"validity":{"state":"active"},"evidence":[occurrence_artifact["digest"]],"subject":subject,"kind":kind,"value":value}
    event=Stream(root).append("observation.recorded",observation,actor="rat-observe",task_id=task["task_id"])
    return {"observation_id":observation["observation_id"],"occurrence_id":occurrence["occurrence_id"],"occurrence_digest":occurrence_artifact["digest"],"quality":level,"event_id":event["event_id"]}
