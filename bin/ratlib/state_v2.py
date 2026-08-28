"""Append-only STATE v2 stream, materialization, and lifecycle validation."""
from __future__ import annotations
import hashlib, json, os, fcntl, re, sys, uuid
from datetime import datetime, timezone
from typing import Any
from .artifact import get, metadata, put_bytes
from .schema import validate

EVENT_SCHEMA="rat.state-event/v2"; TRANSITIONS={
 "proposed":{"supported","refuted"}, "supported":{"confirmed","verified","refuted","stale"},
 "confirmed":{"verified","refuted","invalidated"}, "verified":{"consumed","refuted","invalidated"},
 "consumed":{"invalidated"}, "refuted":set(), "invalidated":set(), "stale":{"supported","refuted"}}
PRIMITIVE_TRANSITIONS={
 ("candidate","pass"), ("candidate","fail"), ("candidate","blocked"),
 ("pass","stale"), ("pass","consumed"), ("blocked","candidate"), ("stale","candidate"),
}
# Controlled vocabulary for L1 failure classification (compounding loop). Fail-closed:
# bin/state and the direct API reject any class outside this set.
FAILURE_CLASSES={"route-miss","offset-wrong","libc-mismatch","env","tooling-gap","timeout","other"}
MIGRATION_TYPES={
 "run.initialized", "observation.recorded", "finding.revised", "primitive.revised",
 "hypothesis.recorded", "route.ruled_out", "alert.recorded", "next.recorded",
 "note.recorded", "migration.diagnostic", "migration.completed",
}
# Allow-list of first-party SELF-measurement verifiers whose successful output may
# back a "direct" observation. The trust root is producer identity by CONTENT
# (build_digest), never an absolute executable path -- so a team snapshot minted in
# one checkout still validates in another checkout of the same verifier bytes.
DIRECT_EVIDENCE_TOOLS={"gdbq","symsolve","symsolve.py"}
# Separate trust root for verification-report PRODUCERS (rat-verify). Distinct from
# DIRECT_EVIDENCE_TOOLS (SELF-observation issuers) because a verification report
# proves a different claim (deterministic re-execution passed), not a SELF measurement.
VERIFY_REPORT_PRODUCERS={"rat-verify"}
VERIFIER_CONTRACT_VERSION="rat.direct-evidence/v2"
# Measurement-intent gate. A "direct" observation must come from a real measurement
# of a challenge subject, not from a verifier's own diagnostics. DENY tokens never
# measure a challenge; REQUIRE tokens (when set for a producer) name the modes that
# actually run one. selftest/--help therefore can never mint direct evidence.
DIRECT_MODE_DENY={"selftest","--selftest","--selfcheck","-h","--help","help","--version","-V"}
DIRECT_MODE_REQUIRE={
 "symsolve":{"--find","--find-str"},
 "symsolve.py":{"--find","--find-str"},
 # gdbq measures whatever batch it is handed; any non-denied invocation with a
 # named subject qualifies.
 "gdbq":None,
}
def _repo_root():
 return os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
def _file_digest(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for chunk in iter(lambda:f.read(65536),b""): h.update(chunk)
 return "sha256:"+h.hexdigest()
def _registry_path(path):
 return os.path.realpath(os.path.abspath(path))
def _default_direct_verifiers():
 repo=_repo_root()
 candidates={
  "gdbq":[os.path.join(repo,"bin","gdbq")],
  "symsolve":[os.path.join(repo,"bin","symsolve")],
  "symsolve.py":[os.path.join(repo,"solve","_template","rev","symsolve.py")],
  # rat-verify's actual verdict logic lives in analysis.py (bin/rat-verify is a
  # thin argv-forwarding wrapper); trust binds to the module that computes verdicts.
  "rat-verify":[os.path.join(repo,"bin","ratlib","analysis.py")],
 }
 out={}
 for producer,paths in candidates.items():
  for path in paths:
   if os.path.isfile(path):
    out.setdefault(producer,set()).add(_file_digest(path))
 return out
def _load_known_build_digests():
 """Optional manifest of past-verifier build digests -> producer.

 Lets snapshots produced by an earlier verifier build keep validating after the
 local checkout is upgraded (version skew). The registry is a committed trust
 artifact: a missing or malformed registry is an installation error, not an
 implicit decision to invalidate every historical snapshot.
 """
 path=os.path.join(_repo_root(),"schemas","direct-verifiers.manifest.json")
 try:
  with open(path,"rb") as f: raw=json.loads(f.read())
 except (OSError, ValueError) as exc:
  raise RuntimeError("direct verifier registry is missing or invalid: %s" % path) from exc
 out={}
 if not isinstance(raw,dict): raise RuntimeError("direct verifier registry must be an object")
 for digest,producer in raw.items():
  if not (isinstance(digest,str) and re.fullmatch(r"sha256:[0-9a-f]{64}",digest) and producer in DIRECT_EVIDENCE_TOOLS|VERIFY_REPORT_PRODUCERS):
   raise RuntimeError("direct verifier registry contains an invalid entry")
  out[digest]=producer
 return out
TRUSTED_DIRECT_VERIFIERS=_default_direct_verifiers()   # producer -> {build_digest, ...}
KNOWN_BUILD_DIGESTS=_load_known_build_digests()          # build_digest -> producer (historical)
def trusted_producer_for_build(build_digest):
 """Resolve a build_digest to its trusted producer, path-independently."""
 if not _is_digest(build_digest): return None
 for producer,digests in TRUSTED_DIRECT_VERIFIERS.items():
  if build_digest in digests: return producer
 return KNOWN_BUILD_DIGESTS.get(build_digest)
def environment_fingerprint():
 """Canonical digest of the measurement host environment, bound into direct evidence.

 Tooling-owned, never caller-chosen: it is stamped into the evidence policy at
 issuance time so a PASS cannot claim an ``environment_digest`` its SELF evidence
 did not actually measure. Coarse (os/arch/libc) but deterministic on a host, so
 the three independent SELF measurements of one primitive agree on it.
 """
 import platform as _platform
 desc={"os":sys.platform,"machine":_platform.machine(),"libc":"".join(_platform.libc_ver())}
 return "sha256:"+hashlib.sha256(json.dumps(desc,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def direct_measurement_policy(build_digest, argv, input_paths, subject_path):
 """Mint a direct-evidence policy for a genuine measurement of a challenge subject.

 Returns None (=> derived) unless the run is a trusted verifier build, in a real
 measurement mode (see DIRECT_MODE_*), that actually consumed ``subject_path`` as a
 recorded input. The policy carries a portable identity ({producer, build_digest,
 registry, subject_digest, environment_digest, mode}) with NO absolute path. The
 subject_digest and environment_digest are what bind a downstream PASS to the exact
 binary and host it claims (see the PASS gate in _validate_payload).
 """
 producer=trusted_producer_for_build(build_digest)
 if not producer: return None
 tokens=[str(a) for a in (argv or [])]
 if any(t in DIRECT_MODE_DENY for t in tokens): return None
 require=DIRECT_MODE_REQUIRE.get(producer)
 if require is not None and not (set(tokens)&require): return None
 paths=list(input_paths or [])
 if not subject_path or subject_path not in paths or not os.path.isfile(subject_path): return None
 mode=next((t for t in tokens if require and t in require), "measure")
 return {"level":"direct","promotion_allowed":True,"producer":producer,
         "registry":VERIFIER_CONTRACT_VERSION,"build_digest":build_digest,
         "subject_digest":_file_digest(subject_path),
         "environment_digest":environment_fingerprint(),"mode":mode}
def direct_evidence_policy_for_executable(path, build_digest=None):
 """Base (subject-free) policy for a registered verifier path. Test/plumbing helper.

 Trust is resolved by content (build_digest), not by ``path``; a full direct policy
 additionally binds a subject via ``direct_measurement_policy``.
 """
 digest=build_digest or (_file_digest(path) if os.path.isfile(path) else None)
 producer=trusted_producer_for_build(digest)
 if not producer: return None
 return {"level":"direct","promotion_allowed":True,"producer":producer,
         "registry":VERIFIER_CONTRACT_VERSION,"build_digest":digest}
def _direct_artifacts_are_present(artifacts, root):
 if not isinstance(artifacts,list) or not artifacts: return False
 has_nonempty_capture=False
 for artifact in artifacts:
  if not isinstance(artifact,dict) or not _is_digest(artifact.get("digest")):
   return False
  try: data=get(artifact["digest"],root=root)
  except Exception as exc: raise ValueError("direct evidence nested artifact is missing or corrupt") from exc
  size=artifact.get("size")
  if size is not None and size != len(data): return False
  if len(data)>0 and artifact.get("kind") in {"stdout","stderr","measurement","execution-trace","tool-capture"}:
   has_nonempty_capture=True
 return has_nonempty_capture
def _classify_evidence(digest, root):
 """Classify one evidence artifact and, when direct, surface what it measured.

 Returns ``{"level","subject_digest","environment_digest"}``. ``subject_digest`` and
 ``environment_digest`` are non-None ONLY for 'direct' evidence, where they name the
 exact binary and host the trusted verifier measured (read from the envelope's own
 hashed bytes). Callers that bind a claim to its evidence (the PASS gate) compare
 these against the claim's ``input_digest`` / ``environment_digest``.
 """
 try: raw=get(digest,root=root)
 except Exception as exc: raise ValueError("observation evidence artifact is missing or corrupt") from exc
 result={"level":"heuristic","subject_digest":None,"environment_digest":None}
 try: doc=json.loads(raw)
 except (ValueError,TypeError): doc=None
 if not (isinstance(doc,dict) and doc.get("schema")=="rat.tool-result/v1" and doc.get("status")=="ok"):
  return result
 result["level"]="derived"
 policy=(doc.get("extensions") or {}).get("evidence_policy") or {}
 producer=policy.get("producer")
 tool=doc.get("tool") or {}
 build_digest=tool.get("build_digest")
 trusted_producer=trusted_producer_for_build(build_digest)
 subject_digest=policy.get("subject_digest")
 environment_digest=policy.get("environment_digest")
 input_digests={i.get("digest") for i in (doc.get("inputs") or []) if isinstance(i,dict)}
 summary=doc.get("summary") or {}
 exit_info=doc.get("exit") or {}
 # A policy label alone is not direct evidence.  Trust binds to producer identity
 # by CONTENT (build_digest, path-independent -> portable across checkouts) AND to a
 # real measured subject recorded in the envelope's inputs: a verifier run that
 # measured no challenge (selftest/--help carries no subject_digest) stays derived.
 # The environment_digest is likewise tooling-stamped; direct evidence must carry
 # both so a downstream PASS can be bound to the binary AND host it was gathered on.
 if (policy.get("level")=="direct" and policy.get("promotion_allowed") is True
     and isinstance(producer,str) and trusted_producer==producer
     and policy.get("registry")==VERIFIER_CONTRACT_VERSION
     and policy.get("build_digest")==build_digest
     and tool.get("name")==producer and _is_digest(build_digest)
     and build_digest != "sha256:" + "0" * 64
     and _is_digest(subject_digest) and subject_digest in input_digests
     and _is_digest(environment_digest)
     and exit_info.get("code")==0 and exit_info.get("timed_out") is False
     and exit_info.get("cancelled") is False and summary.get("truncated") is False
     and _direct_artifacts_are_present(doc.get("artifacts"),root)):
  result.update(level="direct",subject_digest=subject_digest,environment_digest=environment_digest)
 return result
def _evidence_quality(digests, root):
 """Derive an observation's quality from producer-owned, hash-covered evidence.

 'direct' is granted only when EVERY cited artifact is a rat.tool-result/v1 envelope
 with status 'ok' whose ``extensions.evidence_policy`` names an allow-listed producer.
 That policy lives inside the envelope's hashed bytes (read via ``get``), so it cannot
 be forged by editing the mutable metadata sidecar or by relabelling an observation.
 A successful envelope from any other tool is 'derived'; anything else is 'heuristic'.

 Trust boundary: this defends against accidental overclaiming (an observation
 mislabeled 'direct' by tooling), not an adversarial local user. Anyone with
 write access to this checkout can edit TRUSTED_DIRECT_VERIFIERS to allow-list
 their own executable, then run it to mint a self-consistent 'direct' envelope.
 There is no signed producer identity separating "ran an allow-listed verifier"
 from "controls the allow-list" on a single local machine -- that separation
 exists only across the team-sync trust boundary (see validate_history).
 """
 levels=[_classify_evidence(d,root)["level"] for d in digests]
 if levels and all(l=="direct" for l in levels): return "direct"
 if levels and all(l in {"direct","derived"} for l in levels): return "derived"
 return "heuristic"
def _measurement_claims(digests, root):
 """Subject/environment pairs measured by an observation's direct evidence.

 Every returned pair comes from a 'direct' envelope; derived/heuristic artifacts
 contribute nothing. A PASS binds against these so its ``input_digest`` /
 ``environment_digest`` cannot name a binary or host its SELF evidence never touched.
 """
 out=[]
 for d in digests:
  c=_classify_evidence(d,root)
  if c["level"]=="direct":
   out.append((c["subject_digest"],c["environment_digest"]))
 return out
def now(): return datetime.now(timezone.utc).isoformat()
def rat_dir(challenge_dir=None): return os.path.join(os.path.abspath(challenge_dir or os.getcwd()),".rat")
def stream_path(challenge_dir=None): return os.path.join(rat_dir(challenge_dir),"events","STATE.v2.jsonl")
def _id(prefix): return prefix+"_"+uuid.uuid4().hex
def cursor(e): return {"stream_id":e["stream_id"],"seq":e["seq"]}
def _is_digest(value): return isinstance(value,str) and re.fullmatch(r"sha256:[0-9a-f]{64}",value) is not None
def _toint(value):
 if isinstance(value,int): return value
 if isinstance(value,str):
  text=value.strip()
  try: return int(text,0)
  except ValueError:
   try: return int(text,16)
   except ValueError: return None
 return None
def _challenge_root_from_path(path):
 p=os.path.abspath(path or os.getcwd())
 if os.path.isdir(p): return p
 if p.endswith(os.path.join(".rat","events","STATE.v2.jsonl")):
  return os.path.dirname(os.path.dirname(os.path.dirname(p)))
 if os.path.basename(p)=="STATE.jsonl":
  return os.path.dirname(p)
 raise ValueError("path is not a challenge directory, STATE.jsonl root hint, or STATE.v2.jsonl")
def trusted_offset_inputs(challenge_dir=None):
 root=_challenge_root_from_path(challenge_dir or os.getcwd())
 stream=Stream(root)
 view=stream.view()
 # Fail closed if any cited evidence object is missing/corrupt (content-hash check
 # via get); the projection re-derives trust from the object bytes, not the sidecar.
 for obs in view["observations"].values():
  for digest in obs.get("evidence",[]):
   try:
    get(digest,root=stream.root)
   except Exception as exc:
    raise ValueError("trusted offset evidence artifact is missing or corrupt: %s" % digest) from exc
 return view, stream.root
def project_trusted_offsets(view, artifact_root):
 offsets={}
 for obs in view.get("observations",{}).values():
  if obs.get("validity",{}).get("state")!="active": continue
  if obs.get("quality",{}).get("level")!="direct": continue
  if obs.get("kind")!="pwn.offset": continue
  value=obs.get("value",{})
  key=value.get("key"); offset=_toint(value.get("offset"))
  if not isinstance(key,str) or not key or offset is None or offset < 0:
   raise ValueError("malformed pwn.offset observation")
  evidence=obs.get("evidence",[])
  if not evidence: raise ValueError("trusted pwn.offset requires evidence")
  # Re-derive trust from the producer-owned envelope bytes at projection time; a
  # stale quality label on the observation is never taken on faith.
  if _evidence_quality(evidence,artifact_root)!="direct":
   raise ValueError("pwn.offset evidence is not direct/promotion-allowed")
  if key in offsets and offsets[key] != offset:
   raise ValueError("conflicting trusted pwn.offset for %s" % key)
  offsets[key]=offset
 return offsets
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
 def _materialize(self, events, until=None):
  observations={}; findings={}; primitives={}; hypotheses={}; ruled_out={}; unknowns={}; next_probes=[]; notes=[]; alerts=[]; failures=[]; invalid=set()
  for e in events:
   if until and e["seq"]>until: break
   p=dict(e["payload"]); t=e["type"]
   if t=="observation.recorded": observations[p["observation_id"]]=p
   elif t=="finding.revised": findings[p["finding_id"]]=p
   elif t=="primitive.revised": primitives[p["primitive_id"]]=p
   elif t=="primitive.consumed" and p["primitive_id"] in primitives:
    primitive=primitives[p["primitive_id"]]
    if primitive.get("status")=="pass" and primitive.get("input_digest")==p["input_digest"] and primitive.get("environment_digest")==p["environment_digest"]:
     primitive["status"]="consumed"
   elif t=="hypothesis.recorded": hypotheses[p.get("hypothesis_id",e["event_id"])]=p
   elif t=="route.ruled_out": ruled_out[p.get("fingerprint",e["event_id"])]=p
   elif t=="unknown.recorded": unknowns[p.get("unknown_id",e["event_id"])]=p
   elif t=="next.recorded": next_probes.append(p)
   elif t=="note.recorded": notes.append(p)
   elif t=="alert.recorded": alerts.append(p)
   elif t=="failure.classified": failures.append(p)
   elif t=="evidence.invalidated": invalid.update(p.get("observation_ids",[]))
  for oid in invalid:
   if oid in observations: observations[oid]["validity"]={"state":"invalidated","event_id":"cascade"}
  for f in findings.values():
   if set(f.get("evidence_observation_ids",[])) & invalid and f.get("state") not in ("refuted","invalidated"):
    f["state"]="invalidated" if f.get("state")=="confirmed" else "stale"
  for p in primitives.values():
   if set(p.get("self_evidence",[])) & invalid and p.get("status") != "fail":
    p["status"]="stale"
  return {"observations":observations,"findings":findings,"primitives":primitives,"hypotheses":hypotheses,"ruled_out":ruled_out,"unknowns":unknowns,"next_probes":next_probes,"notes":notes,"alerts":alerts,"failures":failures}
 def _validate_migration(self, typ, payload):
  if typ not in MIGRATION_TYPES: raise ValueError("migration actor cannot append %s" % typ)
  if typ in {"migration.diagnostic","migration.completed"}:
   if not _is_digest(payload.get("v1_digest")):
    raise ValueError("migration event requires v1_digest")
   return
  if not isinstance(payload.get("legacy_source_id"),str) or not payload["legacy_source_id"]:
   raise ValueError("migration mapping requires legacy_source_id")
  if not isinstance(payload.get("legacy_line"),int) or payload["legacy_line"] <= 0:
   raise ValueError("migration mapping requires positive legacy_line")
  if not isinstance(payload.get("legacy"),dict):
   raise ValueError("migration mapping requires legacy provenance")
  if typ=="observation.recorded":
   if payload.get("quality",{}).get("level")!="derived" or payload.get("validity",{}).get("state")!="active":
    raise ValueError("legacy observations must remain active derived")
   if payload.get("quality",{}).get("source") in {"direct","self"}:
    raise ValueError("legacy observations cannot be direct")
  elif typ=="finding.revised" and payload.get("state") not in {"supported","stale"}:
   raise ValueError("legacy findings cannot be confirmed or verified")
  elif typ=="primitive.revised" and (payload.get("status")!="candidate" or payload.get("self_evidence",[]) != []):
   raise ValueError("legacy primitives can only be empty-SELF candidates")
 def _canonicalize_payload(self, typ, payload, events, *, actor, task_id):
  """Fill direct-API shorthand into the same public documents the CLI accepts.

  STATE v2 stores full typed documents.  The small Python helpers historically
  accepted shorthand payloads, which made peer replay less strict than the
  `state event append` command.  Normalize at the only write boundary so both
  paths persist and replay exactly the same contract.
  """
  if actor == "migration" or typ not in {"observation.recorded", "finding.revised", "primitive.revised"}:
   return payload
  p=dict(payload); stamp=now(); view=self._materialize(events)
  if typ=="observation.recorded":
   defaults={"schema":"rat.observation/v1","run_id":task_id,"created_at":stamp,
             "producer":{"role":actor},"subject":{},"kind":"unspecified","value":None}
  elif typ=="finding.revised":
   old=view["findings"].get(p.get("finding_id"),{})
   defaults={"schema":"rat.finding/v1","revision":old.get("revision",0)+1,
             "run_id":task_id,"created_at":old.get("created_at",stamp),"updated_at":stamp,
             "title":p.get("finding_id","unspecified"),"class":"unspecified",
             "confidence":0.0,"impact":{},"subject":{},"assumptions":[],
             "contradictions":[],"related_findings":[],"producer_role":actor,"owner_task_id":task_id}
  else:
   old=view["primitives"].get(p.get("primitive_id"),{})
   defaults={"schema":"rat.primitive/v1","name":p.get("primitive_id","unspecified"),
             "class":"unspecified","constraints":[],"side_effects":[],
             "remote_equivalent":False,"producer":{"role":actor},"revision":old.get("revision",0)+1}
  for key,value in defaults.items(): p.setdefault(key,value)
  return p
 def _validate_payload(self, typ, payload, events, actor):
  """Keep the direct API on the same typed path as the ``state`` CLI.

  Old v1 migrations are intentionally admitted as derived legacy records; all
  newly-produced observations must carry content-addressed evidence.
  """
  if not isinstance(typ,str) or not isinstance(payload,dict): raise ValueError("state event type and payload must be objects")
  legacy=actor=="migration"
  if legacy: self._validate_migration(typ,payload)
  elif typ in MIGRATION_TYPES and typ.startswith("migration."):
   raise ValueError("migration events require migration actor")
  view=self._materialize(events)
  if not legacy:
   expected={"observation.recorded":"rat.observation/v1","finding.revised":"rat.finding/v1","primitive.revised":"rat.primitive/v1"}.get(typ)
   if expected: validate(payload,expected)
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
     # Quality is a property of immutable, hash-covered producer output, never a
     # caller assertion. It is derived from the evidence envelopes' own bytes so a
     # caller cannot promote to direct by editing the metadata sidecar or relabelling
     # the observation. P2's promotion_allowed=false outputs stay heuristic.
     payload["quality"]={"level":_evidence_quality(evidence,self.root)}
  elif typ=="finding.revised":
   if not isinstance(payload.get("finding_id"),str) or payload.get("state") not in TRANSITIONS: raise ValueError("finding revision requires id and state")
   if not isinstance(payload.get("evidence_observation_ids",[]),list): raise ValueError("finding evidence must be a list")
   if not legacy:
    old=view["findings"].get(payload["finding_id"]); new=payload["state"]
    # revision is a caller-suppliable field (the direct API only DEFAULTS it via
    # _canonicalize_payload; an explicit value bypasses that default), so it must
    # be checked here too or a caller can record negative/duplicate/skipped
    # revisions that break any consumer assuming a dense 1..N sequence.
    expected_revision=(old.get("revision",0) if old else 0)+1
    if payload.get("revision")!=expected_revision: raise ValueError("finding revision must be %d (got %r)" % (expected_revision, payload.get("revision")))
    if not old and new!="proposed": raise ValueError("initial finding revision must be proposed")
    if new!="proposed" and not payload.get("evidence_observation_ids"): raise ValueError("finding requires evidence")
    if old and new not in TRANSITIONS.get(old["state"],set()): raise ValueError("illegal finding transition")
    if new!="proposed":
     for oid in payload["evidence_observation_ids"]:
      if oid not in view["observations"]: raise ValueError("finding evidence cites unknown observation_id")
      if view["observations"][oid].get("validity",{}).get("state")!="active": raise ValueError("finding evidence cites inactive observation_id")
    # confirmed AND verified both claim strong evidence; verified is reachable
    # directly from supported (see TRANSITIONS) so it must carry the same
    # active+direct requirement as confirmed, not just a non-empty ID list.
    if new in ("confirmed","verified") and not any(view["observations"].get(x,{}).get("quality",{}).get("level")=="direct" and view["observations"].get(x,{}).get("validity",{}).get("state")=="active" for x in payload["evidence_observation_ids"]): raise ValueError("%s finding needs active direct evidence" % new)
  elif typ=="primitive.revised":
   if not isinstance(payload.get("primitive_id"),str) or payload.get("status") not in {"candidate","pass","fail","blocked","stale"}: raise ValueError("primitive revision requires id and status")
   if not isinstance(payload.get("self_evidence",[]),list): raise ValueError("primitive SELF evidence must be a list")
   if not legacy:
    old=view["primitives"].get(payload["primitive_id"]); new=payload["status"]
    expected_revision=(old.get("revision",0) if old else 0)+1
    if payload.get("revision")!=expected_revision: raise ValueError("primitive revision must be %d (got %r)" % (expected_revision, payload.get("revision")))
    if not old and new!="candidate": raise ValueError("initial primitive revision must be candidate")
    if old and (old.get("status"),new) not in PRIMITIVE_TRANSITIONS: raise ValueError("illegal primitive transition")
    if new=="pass":
     self_ids=set(payload.get("self_evidence",[]))
     if len(self_ids) < 3: raise ValueError("PASS needs three distinct active direct SELF observations")
     if not _is_digest(payload.get("input_digest")): raise ValueError("PASS requires input_digest")
     if not _is_digest(payload.get("environment_digest")): raise ValueError("PASS requires environment_digest")
     if not all(view["observations"].get(x,{}).get("quality",{}).get("level")=="direct" and view["observations"].get(x,{}).get("validity",{}).get("state")=="active" for x in self_ids): raise ValueError("PASS needs three active direct SELF observations")
     # Three distinct observation IDs are not enough: an agent could record one
     # measurement three times under different IDs. Require the union of their
     # evidence artifacts to hold >=3 distinct digests, so PASS rests on three
     # genuinely independent measurements, not one relabelled thrice.
     distinct_evidence=set()
     for x in self_ids: distinct_evidence.update(view["observations"].get(x,{}).get("evidence",[]))
     if len(distinct_evidence) < 3: raise ValueError("PASS needs three distinct evidence artifacts across its SELF observations")
     # Bind the claim to its evidence.  Distinct, direct, active SELF observations
     # are still not enough if they measured a DIFFERENT binary or host: three
     # measurements of subject A cannot PASS a primitive claiming subject B in some
     # arbitrary environment. Re-derive what each direct envelope actually measured
     # from its own hashed bytes and require every one to match this PASS's claim.
     input_digest=payload["input_digest"]; environment_digest=payload["environment_digest"]
     for x in self_ids:
      claims=_measurement_claims(view["observations"].get(x,{}).get("evidence",[]),self.root)
      if not claims: raise ValueError("PASS SELF observation carries no direct measurement to bind")
      if any(subj!=input_digest for subj,_env in claims):
       raise ValueError("PASS SELF evidence must measure the primitive input_digest")
      if any(env!=environment_digest for _subj,env in claims):
       raise ValueError("PASS SELF evidence must measure the primitive environment_digest")
  elif typ=="primitive.consumed":
   if not all(isinstance(payload.get(k),str) and payload[k] for k in ("primitive_id","input_digest","environment_digest")): raise ValueError("primitive consumption requires provenance")
   p=view["primitives"].get(payload["primitive_id"])
   if not p or p.get("status")!="pass": raise ValueError("primitive is not an active PASS")
   if p.get("input_digest")!=payload["input_digest"] or p.get("environment_digest")!=payload["environment_digest"]: raise ValueError("primitive environment mismatch")
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
  elif typ=="note.recorded":
   if not isinstance(payload.get("note_id"),str) or not payload["note_id"]: raise ValueError("note requires note_id")
  elif typ=="alert.recorded":
   if not isinstance(payload.get("alert_id"),str) or not payload["alert_id"]: raise ValueError("alert requires alert_id")
  elif typ=="failure.classified":
   if not isinstance(payload.get("failure_id"),str) or not payload["failure_id"]: raise ValueError("failure requires failure_id")
   if payload.get("class") not in FAILURE_CLASSES: raise ValueError("failure class must be one of %s" % sorted(FAILURE_CLASSES))
  elif typ=="run.initialized":
   if not isinstance(payload.get("challenge"),str) or not payload["challenge"]: raise ValueError("run initialization requires challenge")
  elif typ=="migration.diagnostic":
   if "raw_artifact" in payload:
    digest=payload["raw_artifact"]
    if not _is_digest(digest): raise ValueError("migration diagnostic raw_artifact must be a sha256 digest")
    try: metadata(digest,root=self.root)
    except Exception as exc: raise ValueError("migration diagnostic raw_artifact is missing or corrupt") from exc
   if not isinstance(payload.get("malformed_lines",[]),list): raise ValueError("migration diagnostic requires malformed_lines")
  elif typ=="migration.completed":
   if not isinstance(payload.get("last_byte_offset"),int): raise ValueError("migration completion requires byte offset")
   if not isinstance(payload.get("malformed_lines",[]),list): raise ValueError("migration completion requires malformed_lines")
  elif typ=="checkpoint.created":
   if payload.get("schema")!="rat.checkpoint/v1" or not isinstance(payload.get("checkpoint_id"),str):
    raise ValueError("checkpoint requires rat.checkpoint/v1 payload")
  elif typ=="governor.checked":
   if not isinstance(payload.get("action"),str) or not payload["action"]: raise ValueError("governor.checked requires action")
   if not isinstance(payload.get("novel"),bool): raise ValueError("governor.checked requires novel bool")
   if not isinstance(payload.get("digest"),str) or not payload["digest"]: raise ValueError("governor.checked requires digest")
  elif typ in ("phase.entered","phase.exited","phase.rollback","phase.rolled_back",
               "task.started","task.finished","task.cancelled","task.staled",
               "task.late_output","task.output_quarantined",
               "fanout.planned","fanout.converged","skeptic.reported",
               "verification.recorded","verification.staled"):
   # Orchestration / task / fanout / skeptic / verification events. For a LOCAL
   # append(), the emitting layer (ratlib.orchestration) has already gated the
   # payload's semantics (phase transitions, task ownership, skeptic linkage,
   # etc) before calling append(). But validate_history() replays an imported
   # peer stream through THIS function directly -- it never goes through
   # orchestration.py's gates -- so "the emitting layer owns it" is not actually
   # true for that caller. Enforce the minimum structural shape every one of
   # these payloads always has, so a malformed or adversarial peer event fails
   # closed here instead of being materialized as if a local writer produced it.
   if typ in {"phase.entered","phase.rollback","phase.rolled_back"}:
    if not isinstance(payload.get("phase"),str) or not payload["phase"]: raise ValueError("%s requires phase" % typ)
   elif typ=="phase.exited":
    if not isinstance(payload.get("phase"),str) or not payload["phase"] or not isinstance(payload.get("terminal"),bool):
     raise ValueError("phase.exited requires phase and terminal bool")
   elif typ in {"task.started","task.finished","task.cancelled","task.staled","task.output_quarantined"}:
    if (payload.get("schema")!="rat.task-event/v1" or not isinstance(payload.get("task_id"),str) or not payload["task_id"]
        or not isinstance(payload.get("phase"),str) or not payload["phase"]
        or not isinstance(payload.get("role"),str) or not payload["role"]
        or not isinstance(payload.get("status"),str) or not payload["status"]):
     raise ValueError("%s requires a rat.task-event/v1 payload with task_id/phase/role/status" % typ)
   elif typ=="task.late_output":
    if not isinstance(payload.get("task_id"),str) or not payload["task_id"] or not _is_digest(payload.get("artifact")):
     raise ValueError("task.late_output requires task_id and artifact digest")
   elif typ=="fanout.planned":
    if (not isinstance(payload.get("fanout_id"),str) or not payload["fanout_id"]
        or not isinstance(payload.get("phase"),str) or not payload["phase"]
        or not isinstance(payload.get("branches"),list)):
     raise ValueError("fanout.planned requires fanout_id/phase/branches")
   elif typ=="fanout.converged":
    if (payload.get("schema")!="rat.converge-report/v1" or not isinstance(payload.get("converge_id"),str) or not payload["converge_id"]
        or not isinstance(payload.get("retained"),list) or not isinstance(payload.get("refuted"),list) or not isinstance(payload.get("unknowns"),list)):
     raise ValueError("fanout.converged requires a rat.converge-report/v1 payload")
   elif typ=="skeptic.reported":
    required={"schema","report_id","run_id","task_id","exploit_task_id","verdict","counterexamples","affected_ids","residual_risks","phase_attempt_id","lineage_id"}
    if set(payload)!=required or payload["schema"]!="rat.skeptic-report/v1" or payload["verdict"] not in {"accept","refute","inconclusive"}:
     raise ValueError("skeptic.reported requires a rat.skeptic-report/v1 payload")
   elif typ in {"verification.recorded","verification.staled"}:
    if not isinstance(payload.get("verification_id"),str) or not payload["verification_id"]:
     raise ValueError("%s requires verification_id" % typ)
  else:
   raise ValueError("unsupported state event type %s" % typ)
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
   payload=self._canonicalize_payload(typ,payload,events,actor=actor,task_id=task_id)
   self._validate_payload(typ,payload,events,actor)
   e={"schema":EVENT_SCHEMA,"stream_id":sid or _id("stream"),"seq":len(events)+1,"event_id":_id("evt"),"at":now(),"actor":actor,"task_id":task_id,"type":typ,"payload":payload,"caused_by":caused_by or []}
   f.seek(0,2); f.write(json.dumps(e,sort_keys=True,separators=(",",":"))+"\n"); f.flush(); os.fsync(f.fileno()); fcntl.flock(f,fcntl.LOCK_UN)
  self._update_manifest(e, payload.get("checkpoint_id") if typ=="checkpoint.created" else None)
  return e
 def _update_manifest(self, event, checkpoint_id=None):
  # Side effect of EVERY append(): the sibling run.json is atomically rewritten
  # to advance its state cursor (stream_id / latest_event_cursor / checkpoint).
  # No-op when run.json is absent; failures are swallowed so telemetry never
  # blocks a state write.
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
  return self._materialize(self.read(),until=until)
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
  if overflow: cp["overflow_artifact"]=overflow["digest"]
  d=os.path.join(self.root,"checkpoints"); os.makedirs(d,exist_ok=True)
  with open(os.path.join(d,cp["checkpoint_id"]+".json"),"w",encoding="utf-8") as f: json.dump(cp,f,sort_keys=True); f.write("\n")
  self.append("checkpoint.created",cp,task_id=task_id); return cp
def validate_history(events, challenge_dir=None, *, artifact_root=None):
 """Replay imported events through append-time semantic validation without writing.

 The team tools receive streams that were copied from another checkout, so a
 syntactically valid JSONL file must still prove it could have been produced by
 the local typed STATE v2 API.

 Trust boundary: evidence quality is re-derived from each envelope's own hashed
 bytes read out of ``artifact_root`` (via _evidence_quality, never the mutable
 metadata sidecar), and the team store independently re-hashes every imported
 object against its digest. This makes a peer's evidence tamper-evident and forces
 it to be a real allow-listed verifier envelope. It does NOT cryptographically
 prove the peer actually ran that verifier -- surfacing a peer PASS as team-visible
 rests on the honest-peer assumption plus the store's integrity checks, which is
 the accepted model. Defending against a peer who fabricates a self-consistent
 envelope would require signed producer tokens (out of scope here).
 """
 stream=Stream(challenge_dir)
 if artifact_root is not None:
  stream.root=os.path.abspath(artifact_root); stream.path=os.path.join(stream.root,"events","STATE.v2.jsonl")
 replay=[]; sid=None
 for n,e in enumerate(events,1):
  stream._valid(e)
  if sid is None: sid=e["stream_id"]
  if e["stream_id"] != sid or e["seq"] != n:
   raise ValueError("non-monotonic state stream")
  payload=json.loads(json.dumps(e["payload"]))
  if e["actor"] != "migration":
   expected={"observation.recorded":"rat.observation/v1","finding.revised":"rat.finding/v1","primitive.revised":"rat.primitive/v1"}.get(e["type"])
   if expected: validate(payload,expected)
  stream._validate_payload(e["type"],payload,replay,e["actor"])
  if payload != e["payload"]:
   raise ValueError("non-canonical state payload at seq %d" % n)
  replay.append(e)
 return stream._materialize(replay)
def revise_finding(stream, doc):
 return stream.append("finding.revised",doc)
def consume_primitive(stream, primitive_id, *, input_digest, environment_digest):
 return stream.append("primitive.consumed",{"primitive_id":primitive_id,"input_digest":input_digest,"environment_digest":environment_digest})
def revise_primitive(stream, doc):
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
  if t=="init": mapped.append(("run.initialized",provenance|{"challenge":e.get("chal") or os.path.basename(d)}))
  elif t=="offset": mapped.append(("observation.recorded",provenance|{"observation_id":prefix,"quality":{"level":"derived"},"validity":{"state":"active"}}))
  elif t=="ok": mapped.append(("finding.revised",provenance|{"finding_id":prefix,"state":"supported","evidence_observation_ids":[]}))
  elif t=="hypothesis": mapped.append(("hypothesis.recorded",provenance|{"hypothesis_id":prefix}))
  elif t=="primitive": mapped.append(("primitive.revised",provenance|{"primitive_id":prefix,"status":"candidate","self_evidence":[],"legacy_status":e.get("status")}))
  elif t=="no": mapped.append(("route.ruled_out",provenance|{"fingerprint":prefix}))
  elif t=="alert": mapped.append(("alert.recorded",provenance|{"alert_id":prefix}))
  elif t=="next": mapped.append(("next.recorded",provenance|{"probe":text or prefix}))
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
