"""Append-only STATE v2 stream, materialization, and lifecycle validation."""
from __future__ import annotations
import hashlib, json, os, fcntl, uuid
from datetime import datetime, timezone
from typing import Any
from .artifact import get, metadata, put_bytes

EVENT_SCHEMA="rat.state-event/v2"; TRANSITIONS={
 "proposed":{"supported","refuted"}, "supported":{"confirmed","verified","refuted","stale"},
 "confirmed":{"verified","refuted","invalidated"}, "verified":{"consumed","refuted","invalidated"},
 "consumed":{"invalidated"}, "refuted":set(), "invalidated":set(), "stale":{"supported","refuted"}}
def now(): return datetime.now(timezone.utc).isoformat()
def rat_dir(challenge_dir=None): return os.path.join(os.path.abspath(challenge_dir or os.getcwd()),".rat")
def stream_path(challenge_dir=None): return os.path.join(rat_dir(challenge_dir),"events","STATE.v2.jsonl")
def _id(prefix): return prefix+"_"+uuid.uuid4().hex
def cursor(e): return {"stream_id":e["stream_id"],"seq":e["seq"]}
class Stream:
 def __init__(self, challenge_dir=None): self.root=rat_dir(challenge_dir); self.path=stream_path(challenge_dir)
 def read(self):
  if not os.path.exists(self.path): return []
  out=[]
  with open(self.path,encoding="utf-8") as f:
   lines=list(f)
  stream_id=None
  for n,line in enumerate(lines,1):
   try:
    e=json.loads(line); self._valid(e)
    if stream_id is None: stream_id=e["stream_id"]
    if e["stream_id"] != stream_id or e["seq"] != len(out)+1:
     raise ValueError("non-monotonic state stream")
    out.append(e)
   except (ValueError,json.JSONDecodeError) as exc:
    # A crash can leave an unterminated final write.  Any complete invalid
    # record is corruption and must not silently hide later evidence.
    if n == len(lines) and not line.endswith("\n"):
     break
    raise ValueError("invalid state event at line %d: %s" % (n, exc)) from exc
  return out
 def _valid(self,e):
  req={"schema","stream_id","seq","event_id","at","actor","task_id","type","payload","caused_by"}
  if set(e)!=req or e["schema"]!=EVENT_SCHEMA or not isinstance(e["seq"],int): raise ValueError("invalid state event")
 def _validate_payload(self, typ, payload, events, actor):
  """Keep the direct API on the same typed path as the ``state`` CLI.

  Old v1 migrations are intentionally admitted as derived legacy records; all
  newly-produced observations must carry content-addressed evidence.
  """
  if not isinstance(typ,str) or not isinstance(payload,dict): raise ValueError("state event type and payload must be objects")
  legacy=actor=="migration"
  if typ=="observation.recorded":
   if not isinstance(payload.get("observation_id"),str) or not payload["observation_id"]: raise ValueError("observation requires observation_id")
   quality,validity=payload.get("quality"),payload.get("validity")
   if not isinstance(quality,dict) or quality.get("level") not in {"direct","derived","heuristic"}: raise ValueError("observation requires valid quality")
   if not isinstance(validity,dict) or validity.get("state")!="active": raise ValueError("observation must start active")
   if any(e["type"]==typ and e["payload"].get("observation_id")==payload["observation_id"] for e in events): raise ValueError("observation_id is immutable and cannot be reused")
   evidence=payload.get("evidence")
   if not legacy and (not isinstance(evidence,list) or not evidence): raise ValueError("observation requires evidence artifact digests")
   if evidence is not None:
    if not isinstance(evidence,list) or not all(isinstance(d,str) for d in evidence): raise ValueError("observation evidence must be a digest list")
    for digest in evidence:
     try: get(digest,root=self.root)
     except Exception as exc: raise ValueError("observation evidence artifact is missing or corrupt") from exc
    if not legacy:
     policies=[]
     for digest in evidence:
      try: policy=metadata(digest,root=self.root).get("provenance",{}).get("evidence_policy",{})
      except Exception as exc: raise ValueError("observation evidence metadata is missing or corrupt") from exc
      policies.append(policy)
     # Quality is a property of immutable producer provenance, never a caller
     # assertion.  In particular P2's promotion_allowed=false outputs can
     # never become direct evidence by relabelling an observation.
     if policies and all(isinstance(p,dict) and p.get("level")=="direct" and p.get("promotion_allowed") is True for p in policies):
      payload["quality"]={"level":"direct"}
     elif policies and all(isinstance(p,dict) and p.get("level") in {"direct","derived"} for p in policies):
      payload["quality"]={"level":"derived"}
     else:
      payload["quality"]={"level":"heuristic"}
  elif typ=="finding.revised":
   if not isinstance(payload.get("finding_id"),str) or payload.get("state") not in TRANSITIONS: raise ValueError("finding revision requires id and state")
   if not isinstance(payload.get("evidence_observation_ids",[]),list): raise ValueError("finding evidence must be a list")
   if not legacy:
    view=self.view(); old=view["findings"].get(payload["finding_id"]); new=payload["state"]
    if not old and new!="proposed": raise ValueError("initial finding revision must be proposed")
    if new!="proposed" and not payload.get("evidence_observation_ids"): raise ValueError("finding requires evidence")
    if old and new not in TRANSITIONS.get(old["state"],set()): raise ValueError("illegal finding transition")
    if new=="confirmed" and not any(view["observations"].get(x,{}).get("quality",{}).get("level")=="direct" and view["observations"].get(x,{}).get("validity",{}).get("state")=="active" for x in payload["evidence_observation_ids"]): raise ValueError("confirmed finding needs active direct evidence")
  elif typ=="primitive.revised":
   if not isinstance(payload.get("primitive_id"),str) or payload.get("status") not in {"candidate","pass","fail","blocked","stale"}: raise ValueError("primitive revision requires id and status")
   if not isinstance(payload.get("self_evidence",[]),list): raise ValueError("primitive SELF evidence must be a list")
   if not legacy:
    view=self.view(); old=view["primitives"].get(payload["primitive_id"]); new=payload["status"]
    if not old and new!="candidate": raise ValueError("initial primitive revision must be candidate")
    if old and (old.get("status"),new) not in {("candidate","pass"),("candidate","fail"),("candidate","blocked"),("pass","stale"),("blocked","candidate"),("stale","candidate")}: raise ValueError("illegal primitive transition")
    if new=="pass" and (len(payload["self_evidence"])<3 or not all(view["observations"].get(x,{}).get("quality",{}).get("level")=="direct" and view["observations"].get(x,{}).get("validity",{}).get("state")=="active" for x in payload["self_evidence"])): raise ValueError("PASS needs three active direct SELF observations")
  elif typ=="primitive.consumed":
   if not all(isinstance(payload.get(k),str) and payload[k] for k in ("primitive_id","input_digest","environment_digest")): raise ValueError("primitive consumption requires provenance")
  elif typ=="evidence.invalidated":
   if not isinstance(payload.get("observation_ids"),list) or not payload["observation_ids"] or not isinstance(payload.get("reason"),str) or not payload["reason"].strip(): raise ValueError("evidence invalidation requires IDs and reason")
  elif typ=="hypothesis.recorded":
   if not isinstance(payload.get("hypothesis_id"),str) or not payload["hypothesis_id"]: raise ValueError("hypothesis requires hypothesis_id")
  elif typ=="unknown.recorded":
   if not isinstance(payload.get("unknown_id"),str) or not payload["unknown_id"]: raise ValueError("unknown requires unknown_id")
  elif typ=="route.ruled_out":
   if not isinstance(payload.get("fingerprint"),str) or not payload["fingerprint"]: raise ValueError("route requires fingerprint")
  elif typ=="next.recorded":
   if not isinstance(payload.get("probe"),str) or not payload["probe"]: raise ValueError("next probe requires probe")
 def append(self, typ, payload, *, actor="local", task_id="local", caused_by=None):
  os.makedirs(os.path.dirname(self.path),mode=0o700,exist_ok=True)
  with open(self.path,"a+",encoding="utf-8") as f:
   fcntl.flock(f,fcntl.LOCK_EX); f.seek(0); events=[]; sid=None; last_valid_offset=0
   lines=list(f)
   for n,line in enumerate(lines,1):
    try:
     e=json.loads(line); self._valid(e)
     if sid is None: sid=e["stream_id"]
     if e["stream_id"] != sid or e["seq"] != len(events)+1:
      raise ValueError("non-monotonic state stream")
     events.append(e)
     last_valid_offset += len(line.encode("utf-8"))
    except (ValueError,json.JSONDecodeError) as exc:
     # Recover an interrupted final append while holding the stream lock.
     # Otherwise a later JSON record would be appended to these bytes and
     # permanently corrupt the state stream.
     if n == len(lines) and not line.endswith("\n"):
      f.seek(last_valid_offset); f.truncate(); f.flush(); os.fsync(f.fileno()); break
     fcntl.flock(f,fcntl.LOCK_UN)
     raise ValueError("invalid state event at line %d: %s" % (n, exc)) from exc
   self._validate_payload(typ,payload,events,actor)
   e={"schema":EVENT_SCHEMA,"stream_id":sid or _id("stream"),"seq":len(events)+1,"event_id":_id("evt"),"at":now(),"actor":actor,"task_id":task_id,"type":typ,"payload":payload,"caused_by":caused_by or []}
   f.seek(0,2); f.write(json.dumps(e,sort_keys=True,separators=(",",":"))+"\n"); f.flush(); os.fsync(f.fileno()); fcntl.flock(f,fcntl.LOCK_UN)
  self._update_manifest(e, payload.get("checkpoint_id") if typ=="checkpoint.created" else None)
  return e
 def _update_manifest(self, event, checkpoint_id=None):
  path=os.path.join(os.path.dirname(self.root),"run.json")
  if not os.path.isfile(path): return
  try:
   from .run_manifest import read, atomic_write, now_iso
   manifest=read(path); manifest["state"]={"stream_id":event["stream_id"],"latest_event_cursor":cursor(event),"latest_checkpoint_id":checkpoint_id or manifest.get("state",{}).get("latest_checkpoint_id")}; manifest["updated_at"]=now_iso(); atomic_write(path,manifest)
  except (OSError,ValueError): pass
 def delta(self, after=None, until=None):
  events=self.read()
  if after:
   sid,seq=after["stream_id"],after["seq"]
   if events and events[0]["stream_id"]!=sid: raise ValueError("cursor stream mismatch")
   events=[e for e in events if e["seq"]>seq]
  if until:
   events=[e for e in events if e["seq"]<=until["seq"]]
  return events
 def view(self, until=None):
  observations={}; findings={}; primitives={}; hypotheses={}; ruled_out={}; unknowns={}; next_probes=[]; invalid=set()
  for e in self.read():
   if until and e["seq"]>until: break
   p=e["payload"]; t=e["type"]
   if t=="observation.recorded": observations[p["observation_id"]]=p
   elif t=="finding.revised": findings[p["finding_id"]]=p
   elif t=="primitive.revised": primitives[p["primitive_id"]]=p
   elif t=="primitive.consumed" and p["primitive_id"] in primitives:
    primitive=primitives[p["primitive_id"]]
    if primitive.get("input_digest")==p["input_digest"] and primitive.get("environment_digest")==p["environment_digest"]: primitive["status"]="consumed"
   elif t=="hypothesis.recorded": hypotheses[p.get("hypothesis_id",e["event_id"])]=p
   elif t=="route.ruled_out": ruled_out[p.get("fingerprint",e["event_id"])]=p
   elif t=="unknown.recorded": unknowns[p.get("unknown_id",e["event_id"])]=p
   elif t=="next.recorded": next_probes.append(p)
   elif t=="evidence.invalidated":
    invalid.update(p.get("observation_ids",[]))
  for oid in invalid:
   if oid in observations: observations[oid]["validity"]={"state":"invalidated","event_id":"cascade"}
  for f in findings.values():
   if set(f.get("evidence_observation_ids",[])) & invalid and f.get("state") not in ("refuted","invalidated"):
    f["state"]="invalidated" if f.get("state")=="confirmed" else "stale"
  for p in primitives.values():
   if set(p.get("self_evidence",[])) & invalid: p["status"]="stale"
  return {"observations":observations,"findings":findings,"primitives":primitives,"hypotheses":hypotheses,"ruled_out":ruled_out,"unknowns":unknowns,"next_probes":next_probes}
 def checkpoint(self, *, phase, task_id, role, reason, max_bytes=32768, lineage_id=None):
  events=self.read(); cur=cursor(events[-1]) if events else {"stream_id":"", "seq":0}; view=self.view()
  active={k:sorted(v) for k,v in view.items() if isinstance(v,dict)}
  small={"cursor":cur, "active":active,
         "events":[{"seq":e["seq"], "type":e["type"], "payload":e["payload"]} for e in events[-100:]]}
  raw=json.dumps(small,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
  overflow=None
  if len(raw)>max_bytes:
   overflow=put_bytes(raw,kind="state-delta-overflow",media_type="application/json",logical_name="delta.json",root=self.root)
   small["events"]=small["events"][-10:]; small["overflow_artifact"]=overflow["digest"]; raw=json.dumps(small,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
  context=put_bytes(raw,kind="state-context",media_type="application/json",logical_name="context.json",root=self.root)
  previous=[e["payload"].get("checkpoint_id") for e in events if e["type"]=="checkpoint.created"]
  try: run_id=json.load(open(os.path.join(os.path.dirname(self.root),"run.json"),encoding="utf-8"))["run_id"]
  except (OSError,ValueError,KeyError): run_id="local"
  cp={"schema":"rat.checkpoint/v1","checkpoint_id":_id("checkpoint"),"run_id":run_id,"created_at":now(),"reason":reason,"phase":phase,"task_id":task_id,"role":role,"lineage_id":lineage_id,"event_cursor":cur,"active":active,"invalidation_cursor":cur,"context_artifact":context["digest"],"budgets":{},"status":"handoff","verified_findings":[i for i,x in view["findings"].items() if x.get("state") in ("confirmed","verified")],"supported_hypotheses":list(view["hypotheses"]),"ruled_out":list(view["ruled_out"]),"unresolved_unknowns":list(view["unknowns"]),"next_probes":view["next_probes"],"supersedes":previous[-1] if previous else None}
  d=os.path.join(self.root,"checkpoints"); os.makedirs(d,exist_ok=True)
  with open(os.path.join(d,cp["checkpoint_id"]+".json"),"w",encoding="utf-8") as f: json.dump(cp,f,sort_keys=True); f.write("\n")
  self.append("checkpoint.created",cp,task_id=task_id); return cp
def revise_finding(stream, doc):
 old=stream.view()["findings"].get(doc["finding_id"]); new=doc["state"]
 if not old and new != "proposed":
  raise ValueError("initial finding revision must be proposed")
 if new != "proposed" and not doc.get("evidence_observation_ids"):
  raise ValueError("finding requires evidence")
 if new=="confirmed":
  obs=stream.view()["observations"]
  if not any(obs.get(x,{}).get("quality",{}).get("level")=="direct" and obs.get(x,{}).get("validity",{}).get("state")=="active" for x in doc["evidence_observation_ids"]): raise ValueError("confirmed finding needs active direct evidence")
 if old:
  if new not in TRANSITIONS.get(old["state"],set()): raise ValueError("illegal finding transition")
 return stream.append("finding.revised",doc)
def consume_primitive(stream, primitive_id, *, input_digest, environment_digest):
 p=stream.view()["primitives"].get(primitive_id)
 if not p or p.get("status")!="pass": raise ValueError("primitive is not an active PASS")
 if p.get("input_digest")!=input_digest or p.get("environment_digest")!=environment_digest: raise ValueError("primitive environment mismatch")
 return stream.append("primitive.consumed",{"primitive_id":primitive_id,"input_digest":input_digest,"environment_digest":environment_digest})
def revise_primitive(stream, doc):
 old=stream.view()["primitives"].get(doc["primitive_id"])
 if not old and doc["status"] != "candidate":
  raise ValueError("initial primitive revision must be candidate")
 if old and (old.get("status"),doc["status"]) not in {
  ("candidate","pass"),("candidate","fail"),("candidate","blocked"),
  ("pass","stale"),("blocked","candidate"),("stale","candidate")
 }:
  raise ValueError("illegal primitive transition")
 if doc["status"]=="pass":
  obs=stream.view()["observations"]
  if len(doc["self_evidence"])<3 or not all(obs.get(x,{}).get("quality",{}).get("level")=="direct" and obs.get(x,{}).get("validity",{}).get("state")=="active" for x in doc["self_evidence"]): raise ValueError("PASS needs three active direct SELF observations")
 return stream.append("primitive.revised",doc)
def migrate_v1(challenge_dir=None,dry_run=False):
 d=os.path.abspath(challenge_dir or os.getcwd()); old=os.path.join(d,"STATE.jsonl"); s=Stream(d)
 if not os.path.exists(old): raise ValueError("STATE.jsonl not found")
 with open(old,"rb") as source: raw=source.read()
 digest="sha256:"+hashlib.sha256(raw).hexdigest()
 events=s.read()
 if any(e["type"]=="migration.completed" and e["payload"].get("v1_digest")==digest for e in events): return {"idempotent":True,"digest":digest,"mapped":0}
 # A process can die after writing only part of the v1 mapping.  Each source
 # line therefore has a deterministic identity; retrying imports only records
 # the missing lines instead of duplicating history before migration.completed.
 imported={e["payload"].get("legacy_source_id") for e in events if e.get("actor")=="migration"}
 mapped=[]; bad=[]
 for n,line in enumerate(raw.splitlines(),1):
  try: e=json.loads(line); t=e.get("t"); text=e.get("text","")
  except Exception: bad.append(n); continue
  prefix="legacy_%s_%d" % (digest[7:19],n); source_id="%s:%d" % (digest,n)
  provenance={"legacy":e,"legacy_line":n,"legacy_source_id":source_id,"text":text}
  if t=="init": mapped.append(("run.initialized",provenance))
  elif t=="offset": mapped.append(("observation.recorded",provenance|{"observation_id":prefix,"quality":{"level":"derived"},"validity":{"state":"active"}}))
  elif t=="ok": mapped.append(("finding.revised",provenance|{"finding_id":prefix,"state":"supported","evidence_observation_ids":[]}))
  elif t=="hypothesis": mapped.append(("hypothesis.recorded",provenance|{"hypothesis_id":prefix}))
  elif t=="primitive": mapped.append(("primitive.revised",provenance|{"primitive_id":prefix,"status":"candidate","self_evidence":[],"legacy_status":e.get("status")}))
  elif t=="no": mapped.append(("route.ruled_out",provenance|{"fingerprint":prefix}))
  elif t=="alert": mapped.append(("alert.recorded",provenance|{"alert_id":prefix}))
  elif t=="next": mapped.append(("next.recorded",provenance|{"probe":prefix}))
  elif t=="note": mapped.append(("note.recorded",provenance|{"note_id":prefix}))
  else: bad.append(n)
 if not dry_run:
  mapped=[(typ,p) for typ,p in mapped if p["legacy_source_id"] not in imported]
  for typ,p in mapped: s.append(typ,p,actor="migration")
  if bad:
   malformed=put_bytes(raw,kind="legacy-state-v1",media_type="application/x-ndjson",logical_name="STATE.jsonl",root=s.root)
   s.append("migration.diagnostic",{"v1_digest":digest,"raw_artifact":malformed["digest"],"malformed_lines":bad},actor="migration")
  s.append("migration.completed",{"v1_digest":digest,"last_byte_offset":len(raw),"malformed_lines":bad},actor="migration")
 return {"idempotent":False,"digest":digest,"mapped":len(mapped),"malformed_lines":bad,"resumed":bool(imported)}
