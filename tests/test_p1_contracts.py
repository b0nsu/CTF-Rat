import json, os, pathlib, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import put_bytes, get, verify
from ratlib.schema import validate, ValidationError
from ratlib.state_v2 import Stream, consume_primitive, direct_evidence_policy_for_executable, migrate_v1, revise_finding, revise_primitive, validate_history
from ratlib.cache import key
from ratlib.contracts import execute
from tests.direct_evidence_helper import direct_evidence_envelope, CANONICAL_SUBJECT, CANONICAL_ENVIRONMENT

D="sha256:"+"a"*64
def observation(stream, oid, level="direct", subject_digest=None):
 if level=="direct":
  digest=direct_evidence_envelope(root=stream.root,producer="gdbq",measurement=b"measurement:"+oid.encode(),summary=oid,subject_digest=subject_digest)
 else:
  digest=put_bytes(oid.encode(),kind="test-evidence",media_type="text/plain",logical_name=oid,root=stream.root)["digest"]
 return {"observation_id":oid,"quality":{"level":level},"validity":{"state":"active"},"evidence":[digest]}
class P1Contracts(unittest.TestCase):
 def test_artifact_is_content_addressed(self):
  with tempfile.TemporaryDirectory() as d:
   one=put_bytes(b"same",kind="x",media_type="text/plain",logical_name="one",root=d)
   two=put_bytes(b"same",kind="x",media_type="text/plain",logical_name="two",root=d)
   self.assertEqual(one["digest"],two["digest"]); self.assertEqual(get(one["digest"],root=d),b"same"); self.assertFalse(verify(root=d))
 def test_result_rejects_oversized_summary(self):
  x={"schema":"rat.tool-result/v1","tool":{"name":"x","version":"1","build_digest":D},"run_id":"r","invocation_id":"i","status":"ok","started_at":"2020-01-01T00:00:00Z","finished_at":"2020-01-01T00:00:00Z","duration_ms":0,"inputs":[],"parameters":{},"summary":"x"*40000,"artifacts":[],"findings":[],"diagnostics":[],"exit":{"code":0,"signal":None,"timed_out":False,"cancelled":False},"provenance":{"platform":{},"dependency_versions":{},"policy_digest":D,"cache":{}}}
  with self.assertRaises(ValidationError): validate(x)
 def test_cache_key_tracks_semantic_inputs(self):
  base=dict(tool={"name":"x","version":"1","build_digest":D},inputs=[],parameters={"base":1},dependencies={},policy_digest=D)
  self.assertNotEqual(key(**base),key(**(base|{"parameters":{"base":2}})))
 def test_invalidation_stales_primitive(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   for oid in ("o1","o2","o3"):
    s.append("observation.recorded",observation(s,oid))
   p={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT}
   revise_primitive(s,p)
   revise_primitive(s,{**p,"status":"pass","self_evidence":["o1","o2","o3"]})
   s.append("evidence.invalidated",{"observation_ids":["o1"],"reason":"test invalidation"})
   self.assertEqual(s.view()["primitives"]["p"]["status"],"stale")
 def test_finding_transition_requires_direct_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); f={"finding_id":"f","state":"proposed","evidence_observation_ids":[]}; revise_finding(s,f)
   with self.assertRaises(ValueError): revise_finding(s,{"finding_id":"f","state":"supported","evidence_observation_ids":[]})
 def test_finding_cannot_start_confirmed_from_heuristic_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   s.append("observation.recorded",observation(s,"heuristic","heuristic"))
   with self.assertRaises(ValueError): revise_finding(s,{"finding_id":"f","state":"confirmed","evidence_observation_ids":["heuristic"]})
 def test_finding_cannot_promote_with_unknown_or_inactive_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); revise_finding(s,{"finding_id":"f","state":"proposed","evidence_observation_ids":[]})
   with self.assertRaisesRegex(ValueError, "unknown observation_id"):
    revise_finding(s,{"finding_id":"f","state":"supported","evidence_observation_ids":["missing"]})
   s.append("observation.recorded",observation(s,"o"))
   s.append("evidence.invalidated",{"observation_ids":["o"],"reason":"bad"})
   with self.assertRaisesRegex(ValueError, "inactive observation_id"):
    revise_finding(s,{"finding_id":"f","state":"supported","evidence_observation_ids":["o"]})
 def test_stream_append_cannot_bypass_finding_or_primitive_lifecycle(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); s.append("observation.recorded",observation(s,"o"))
   with self.assertRaises(ValueError): s.append("finding.revised",{"finding_id":"f","state":"confirmed","evidence_observation_ids":["o"]})
   with self.assertRaises(ValueError): s.append("primitive.revised",{"primitive_id":"p","status":"pass","self_evidence":["o","o","o"]})
   s.append("primitive.revised",{"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":D,"environment_digest":D})
   with self.assertRaises(ValueError): s.append("primitive.revised",{"primitive_id":"p","status":"pass","self_evidence":["o","o","o"],"input_digest":D,"environment_digest":D})
 def test_evidence_quality_is_derived_from_artifact_policy(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   artifact=put_bytes(b"p2",kind="rat-profile",media_type="application/json",logical_name="result.json",root=s.root,provenance={"evidence_policy":{"level":"heuristic","promotion_allowed":False}})
   s.append("observation.recorded",{"observation_id":"p2","quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[artifact["digest"]]})
   self.assertEqual(s.view()["observations"]["p2"]["quality"]["level"],"heuristic")
   with self.assertRaises(ValueError): revise_finding(s,{"finding_id":"f","state":"confirmed","evidence_observation_ids":["p2"]})
 def test_direct_policy_requires_real_tool_identity_and_capture(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   measurement=put_bytes(b"claimed measurement",kind="measurement",media_type="text/plain",logical_name="m",root=s.root)
   forged={"schema":"rat.tool-result/v1","tool":{"name":"gdbq","version":"fake","build_digest":"sha256:"+"0"*64},"run_id":"r","invocation_id":"i","status":"ok","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:00Z","duration_ms":0,"inputs":[],"parameters":{},"summary":{},"artifacts":[{"digest":measurement["digest"]}],"findings":[],"diagnostics":[],"exit":{"code":0,"signal":None,"timed_out":False,"cancelled":False},"provenance":{"platform":{},"dependency_versions":{},"policy_digest":D,"cache":{}},"extensions":{"evidence_policy":{"level":"direct","promotion_allowed":True,"producer":"gdbq"}}}
   evidence=put_bytes(json.dumps(forged).encode(),kind="tool-result",media_type="application/json",logical_name="forged.json",root=s.root)
   s.append("observation.recorded",{"observation_id":"forged","quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[evidence["digest"]]})
   self.assertEqual(s.view()["observations"]["forged"]["quality"]["level"],"derived")
 def test_execute_does_not_promote_arbitrary_gdbq_basename(self):
  with tempfile.TemporaryDirectory() as d:
   tool=pathlib.Path(d,"gdbq")
   tool.write_text("#!/bin/sh\nprintf measured\n",encoding="utf-8")
   tool.chmod(0o755)
   doc=execute([str(tool)],root=os.path.join(d,".rat"),timeout=5)
   digest=doc["extensions"]["envelope_digest"]
   s=Stream(d)
   for oid in ("o1","o2","o3"):
    s.append("observation.recorded",{"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[digest]})
   self.assertEqual(s.view()["observations"]["o1"]["quality"]["level"],"derived")
   p={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":D,"environment_digest":D}
   revise_primitive(s,p)
   with self.assertRaisesRegex(ValueError,"PASS needs three active direct SELF observations"):
    revise_primitive(s,{**p,"status":"pass","self_evidence":["o1","o2","o3"]})
 def test_direct_policy_rejects_missing_nested_artifact(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   tool=os.path.join(os.path.dirname(__file__),"..","bin","gdbq")
   sd="sha256:"+"c"*64
   policy={**direct_evidence_policy_for_executable(tool),"subject_digest":sd,"environment_digest":CANONICAL_ENVIRONMENT,"mode":"measure"}
   forged={"schema":"rat.tool-result/v1","tool":{"name":"gdbq","version":"fake","build_digest":policy["build_digest"]},"run_id":"r","invocation_id":"i","status":"ok","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:00Z","duration_ms":0,"inputs":[{"role":"input","digest":sd,"size":1}],"parameters":{},"summary":{"truncated":False},"artifacts":[{"kind":"stdout","digest":"sha256:"+"b"*64,"media_type":"text/plain","size":8,"logical_name":"missing.txt"}],"findings":[],"diagnostics":[],"exit":{"code":0,"signal":None,"timed_out":False,"cancelled":False},"provenance":{"platform":{},"dependency_versions":{},"policy_digest":D,"cache":{}},"extensions":{"evidence_policy":policy}}
   evidence=put_bytes(json.dumps(forged).encode(),kind="tool-result",media_type="application/json",logical_name="missing-nested.json",root=s.root)
   with self.assertRaisesRegex(ValueError,"nested artifact is missing or corrupt"):
    s.append("observation.recorded",{"observation_id":"missing","quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[evidence["digest"]]})
 def test_production_direct_evidence_helper_is_disabled(self):
  from ratlib.contracts import direct_evidence_envelope as production_helper
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaisesRegex(RuntimeError, "synthetic direct evidence is disabled"):
    production_helper(root=d,producer="gdbq",measurement=b"measurement")
 def test_execute_returns_citeable_direct_envelope_digest(self):
  with tempfile.TemporaryDirectory() as d:
   digest=direct_evidence_envelope(root=os.path.join(d,".rat"),producer="gdbq",measurement=b"measured")
   s=Stream(d)
   s.append("observation.recorded",{"observation_id":"real","quality":{"level":"heuristic"},"validity":{"state":"active"},"evidence":[digest]})
   self.assertEqual(s.view()["observations"]["real"]["quality"]["level"],"direct")
 def _selftest_style_envelope(self, s, producer, nonce):
  # Mimics what execute([verifier,"selftest"]) produced under the old bug: a
  # trusted build_digest and a direct-labelled policy, but NO measured subject
  # (empty inputs / no subject_digest). Must resolve to derived, never direct.
  from ratlib.state_v2 import _file_digest, VERIFIER_CONTRACT_VERSION
  import ratlib.state_v2 as sv2
  tool=os.path.join(os.path.dirname(__file__),"..","bin",producer)
  build=_file_digest(tool)
  self.assertEqual(sv2.trusted_producer_for_build(build),producer)
  cap=put_bytes(b"selftest ran: "+nonce.encode(),kind="stdout",media_type="text/plain",logical_name="stdout.txt",root=s.root)
  doc={"schema":"rat.tool-result/v1","tool":{"name":producer,"version":"legacy-adapter/v1","build_digest":build},"run_id":"r","invocation_id":"i"+nonce,"status":"ok","started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:00Z","duration_ms":0,"inputs":[],"parameters":{"n":nonce},"summary":{"truncated":False},"artifacts":[{k:cap[k] for k in ("kind","digest","media_type","size","logical_name")}],"findings":[],"diagnostics":[],"exit":{"code":0,"signal":None,"timed_out":False,"cancelled":False},"provenance":{"platform":{},"dependency_versions":{},"policy_digest":D,"cache":{}},"extensions":{"evidence_policy":{"level":"direct","promotion_allowed":True,"producer":producer,"registry":VERIFIER_CONTRACT_VERSION,"build_digest":build}}}
  return put_bytes(json.dumps(doc,sort_keys=True,separators=(",",":")).encode(),kind="tool-result",media_type="application/json",logical_name="selftest-%s.json"%nonce,root=s.root)["digest"]
 def test_selftest_runs_cannot_reach_primitive_pass(self):
  # Regression for the "3x symsolve selftest -> PASS" forgery: three distinct
  # no-subject selftest envelopes must stay derived and be rejected at PASS.
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); oids=[]
   for i,nonce in enumerate(("a","b","c")):
    dig=self._selftest_style_envelope(s,"symsolve",nonce)
    oid="obs_%d"%i
    s.append("observation.recorded",{"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[dig]})
    self.assertEqual(s.view()["observations"][oid]["quality"]["level"],"derived")
    oids.append(oid)
   p={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":D,"environment_digest":D}
   revise_primitive(s,p)
   with self.assertRaisesRegex(ValueError,"PASS needs three active direct SELF observations"):
    revise_primitive(s,{**p,"status":"pass","self_evidence":oids})
 def test_pass_succeeds_when_evidence_measures_the_claimed_subject_and_host(self):
  # Positive control: three genuine, distinct direct measurements of the primitive's
  # own binary+host PASS. Guards the binding gate against being trivially unsatisfiable.
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   for oid in ("o1","o2","o3"): s.append("observation.recorded",observation(s,oid))
   p={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT}
   revise_primitive(s,p)
   revise_primitive(s,{**p,"status":"pass","self_evidence":["o1","o2","o3"]})
   self.assertEqual(s.view()["primitives"]["p"]["status"],"pass")
 def test_pass_rejects_evidence_that_measured_a_different_subject(self):
  # BLOCK-1 regression: three genuine direct measurements of binary A must NOT PASS a
  # primitive claiming binary B. The evidence is real and direct; only the subject
  # binding stops the forgery.
  SUBJECT_A="sha256:"+"a"*64; SUBJECT_B="sha256:"+"b"*64
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   for oid in ("o1","o2","o3"):
    s.append("observation.recorded",observation(s,oid,subject_digest=SUBJECT_A))
    self.assertEqual(s.view()["observations"][oid]["quality"]["level"],"direct")
   p={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":SUBJECT_B,"environment_digest":CANONICAL_ENVIRONMENT}
   revise_primitive(s,p)
   with self.assertRaisesRegex(ValueError,"must measure the primitive input_digest"):
    revise_primitive(s,{**p,"status":"pass","self_evidence":["o1","o2","o3"]})
   # One dissenting measurement is enough to block it: two of A, one of B, claim A.
   s.append("observation.recorded",observation(s,"o4",subject_digest=SUBJECT_A))
   s.append("observation.recorded",observation(s,"o5",subject_digest=SUBJECT_A))
   s.append("observation.recorded",observation(s,"o6",subject_digest=SUBJECT_B))
   q={"primitive_id":"q","status":"candidate","self_evidence":[],"input_digest":SUBJECT_A,"environment_digest":CANONICAL_ENVIRONMENT}
   revise_primitive(s,q)
   with self.assertRaisesRegex(ValueError,"must measure the primitive input_digest"):
    revise_primitive(s,{**q,"status":"pass","self_evidence":["o4","o5","o6"]})
 def test_pass_rejects_evidence_that_measured_a_different_environment(self):
  # The environment half of the same binding: evidence gathered on the tooling host
  # cannot PASS a primitive claiming some other environment_digest.
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   for oid in ("o1","o2","o3"): s.append("observation.recorded",observation(s,oid))
   p={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":CANONICAL_SUBJECT,"environment_digest":"sha256:"+"c"*64}
   revise_primitive(s,p)
   with self.assertRaisesRegex(ValueError,"must measure the primitive environment_digest"):
    revise_primitive(s,{**p,"status":"pass","self_evidence":["o1","o2","o3"]})
 def test_direct_evidence_survives_clone_relocation_and_version_skew(self):
  # HIGH-2: a direct envelope must validate by verifier CONTENT, not by the
  # producer machine's absolute path, and keep validating after the local build
  # is upgraded as long as the producing digest is a known (manifested) build.
  import ratlib.state_v2 as sv2
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   digest=direct_evidence_envelope(root=s.root,producer="gdbq",measurement=b"m1")
   env=json.loads(get(digest,root=s.root))
   self.assertNotIn("executable",env["extensions"]["evidence_policy"])  # no absolute path stored
   from ratlib.state_v2 import _file_digest,_evidence_quality
   build=_file_digest(os.path.join(os.path.dirname(__file__),"..","bin","gdbq"))
   saved_trusted,saved_known=sv2.TRUSTED_DIRECT_VERIFIERS,sv2.KNOWN_BUILD_DIGESTS
   try:
    # Verifier upgraded locally (different bytes) AND relocated: the producing
    # build is gone from the live registry but present in the historical manifest.
    sv2.TRUSTED_DIRECT_VERIFIERS={"gdbq":{"sha256:"+"9"*64}}
    sv2.KNOWN_BUILD_DIGESTS={build:"gdbq"}
    self.assertEqual(_evidence_quality([digest],s.root),"direct")
    # With the build in neither the live registry nor the manifest -> downgraded.
    sv2.KNOWN_BUILD_DIGESTS={}
    self.assertEqual(_evidence_quality([digest],s.root),"derived")
   finally:
    sv2.TRUSTED_DIRECT_VERIFIERS,sv2.KNOWN_BUILD_DIGESTS=saved_trusted,saved_known
 def test_live_direct_verifiers_are_recorded_in_history_registry(self):
  import ratlib.state_v2 as sv2
  manifest=pathlib.Path(__file__).resolve().parents[1] / "schemas" / "direct-verifiers.manifest.json"
  registry=json.loads(manifest.read_text(encoding="utf-8"))
  for digests in sv2.TRUSTED_DIRECT_VERIFIERS.values():
   self.assertTrue(digests <= set(registry))
 def test_v1_migration_materializes_legacy_events_without_promoting_pass(self):
  with tempfile.TemporaryDirectory() as d:
   with open(os.path.join(d,"STATE.jsonl"),"w",encoding="utf-8") as f:
    f.write('{"t":"ok","text":"legacy fact"}\n{"t":"primitive","name":"rip","status":"pass","evidence":"old note"}\n')
   self.assertEqual(migrate_v1(d)["mapped"],2)
   view=Stream(d).view()
   self.assertEqual(next(iter(view["findings"].values()))["state"],"supported")
   self.assertEqual(next(iter(view["primitives"].values()))["status"],"candidate")
 def test_v1_migration_resumes_after_interrupted_import_without_duplicates(self):
  with tempfile.TemporaryDirectory() as d:
   legacy=os.path.join(d,"STATE.jsonl")
   with open(legacy,"w",encoding="utf-8") as f: f.write('{"t":"hypothesis","text":"first"}\n{"t":"hypothesis","text":"second"}\n')
   raw=pathlib.Path(legacy).read_bytes(); digest="sha256:"+__import__("hashlib").sha256(raw).hexdigest()
   s=Stream(d)
   s.append("hypothesis.recorded",{"hypothesis_id":"legacy_%s_1" % digest[7:19],"legacy_source_id":"%s:1" % digest,"legacy_line":1,"legacy":{"t":"hypothesis","text":"first"},"text":"first"},actor="migration")
   result=migrate_v1(d)
   self.assertTrue(result["resumed"]); self.assertEqual(result["mapped"],1)
   self.assertEqual(sorted(x["text"] for x in Stream(d).view()["hypotheses"].values()),["first","second"])
   self.assertTrue(migrate_v1(d)["idempotent"])
 def test_state_show_prefers_v2_after_migration(self):
  with tempfile.TemporaryDirectory() as d:
   pathlib.Path(d,"STATE.jsonl").write_text('{"t":"hypothesis","text":"legacy hypothesis"}\n')
   self.assertEqual(migrate_v1(d)["mapped"],1)
   tool=os.path.join(os.path.dirname(__file__),"..","bin","state")
   shown=subprocess.run([tool,"--dir",d,"show"],text=True,capture_output=True,check=True)
   self.assertIn("STATE v2",shown.stdout); self.assertIn("legacy hypothesis",shown.stdout)
   legacy=subprocess.run([tool,"--dir",d,"show","--legacy"],text=True,capture_output=True,check=True)
   self.assertNotIn("STATE v2",legacy.stdout)
 def test_adapter_does_not_cache_timeout_or_drop_spooled_stdout(self):
  with tempfile.TemporaryDirectory() as d:
   slow=[sys.executable,"-c","import time; time.sleep(.2)"]
   first=execute(slow,root=d,timeout=.05)
   second=execute(slow,root=d,timeout=1)
   self.assertEqual(first["status"],"timeout")
   self.assertEqual(second["status"],"ok")
   loud=[sys.executable,"-c","import sys; sys.stdout.write('A'*(9*1024*1024))"]
   result=execute(loud,root=d,parameters={"case":"spool"},timeout=5)
   stdout=next(a for a in result["artifacts"] if a["kind"]=="stdout")
   self.assertEqual(stdout["size"],9*1024*1024)
 def test_checkpoint_tracks_unknowns_and_lineage(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); s.append("unknown.recorded",{"unknown_id":"u","text":"libc version"}); s.append("route.ruled_out",{"fingerprint":"r"})
   first=s.checkpoint(phase="P1",task_id="a",role="scout",reason="first")
   second=s.checkpoint(phase="P2",task_id="b",role="lead",reason="second")
   self.assertEqual(first["unresolved_unknowns"],["u"]); self.assertEqual(second["supersedes"],first["checkpoint_id"])
 def test_append_recovers_partial_tail_before_next_event(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); first=s.append("note.recorded",{"note_id":"first"})
   with open(s.path,"ab") as f: f.write(b'{"partial":')
   second=s.append("note.recorded",{"note_id":"second"})
   events=s.read()
   self.assertEqual([e["seq"] for e in events],[1,2])
   self.assertEqual(events[0]["event_id"],first["event_id"])
   self.assertEqual(events[1]["event_id"],second["event_id"])
 def test_stream_rejects_untyped_or_duplicate_observations(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   with self.assertRaises(ValueError): s.append("observation.recorded",{"observation_id":"o","quality":{"level":"direct"},"validity":{"state":"active"}})
   with self.assertRaises(ValueError): s.append("observation.recorded",{**observation(s,"o"),"evidence":["sha256:"+"0"*64]})
   s.append("observation.recorded",observation(s,"o"))
   with self.assertRaises(ValueError): s.append("observation.recorded",observation(s,"o"))
 def test_consumed_primitive_is_materialized_as_consumed(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   for oid in ("o1","o2","o3"): s.append("observation.recorded",observation(s,oid))
   doc={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT}
   revise_primitive(s,doc); revise_primitive(s,{**doc,"status":"pass","self_evidence":["o1","o2","o3"]})
   consume_primitive(s,"p",input_digest=CANONICAL_SUBJECT,environment_digest=CANONICAL_ENVIRONMENT)
   self.assertEqual(s.view()["primitives"]["p"]["status"],"consumed")
 def test_artifact_gc_is_dry_run_by_default_and_keeps_run_manifest_root(self):
  with tempfile.TemporaryDirectory() as d:
   root=os.path.join(d,".rat"); kept=put_bytes(b"kept",kind="x",media_type="text/plain",logical_name="kept",root=root); orphan=put_bytes(b"orphan",kind="x",media_type="text/plain",logical_name="orphan",root=root)
   pathlib.Path(d,"run.json").write_text(json.dumps({"input":kept["digest"]}))
   tool=os.path.join(os.path.dirname(__file__),"..","bin","rat-artifact")
   first=subprocess.run([tool,"--root",root,"gc"],text=True,capture_output=True,check=True)
   self.assertTrue(json.loads(first.stdout)["dry_run"]); self.assertEqual(get(orphan["digest"],root=root),b"orphan")
   second=subprocess.run([tool,"--root",root,"gc","--apply"],text=True,capture_output=True,check=True)
   self.assertFalse(json.loads(second.stdout)["dry_run"]); self.assertEqual(get(kept["digest"],root=root),b"kept")
   with self.assertRaises(FileNotFoundError): get(orphan["digest"],root=root)
 def test_verification_report_reference_schema_matches_enforced_contract(self):
  # schemas/*.json is a reference doc surfaced by `state schema`, not loaded for
  # validation -- runtime enforcement lives inline in orchestration.py. Guard the
  # two against drift: the JSON's required set must equal what the gate enforces.
  import re
  repo=os.path.join(os.path.dirname(__file__),"..")
  src=pathlib.Path(repo,"bin","ratlib","orchestration.py").read_text()
  # the required={...} literal immediately preceding the verification-report check
  block=src[:src.index('rat.verification-report/v1')]
  enforced=set(re.findall(r'"([^"]+)"',re.findall(r'required=\{[^}]*\}',block)[-1]))
  doc=json.loads(pathlib.Path(repo,"schemas","rat.verification-report.v1.json").read_text())
  self.assertEqual(set(doc["required"]),enforced)
  self.assertEqual(set(doc["properties"]),enforced)
class ValidateHistory(unittest.TestCase):
 """Trust-boundary contract for validate_history: it replays an imported stream
 through append-time semantics WITHOUT writing, and must fail closed on any event
 that could not have been produced by the local typed STATE v2 API. Exercised in
 production by teamsync/teamstate; asserted directly here."""

 def _stream_with_observations(self, d):
  s=Stream(d)
  for oid in ("o1","o2","o3"):
   s.append("observation.recorded",observation(s,oid))
  return s

 def _events(self, d):
  # deep copy via JSON so mutation cannot alias the on-disk stream
  return json.loads(json.dumps(Stream(d).read()))

 def test_accepts_locally_produced_history(self):
  with tempfile.TemporaryDirectory() as d:
   self._stream_with_observations(d)
   view=validate_history(self._events(d), d)
   self.assertEqual(set(view["observations"]), {"o1","o2","o3"})

 def test_rejects_non_monotonic_seq(self):
  with tempfile.TemporaryDirectory() as d:
   self._stream_with_observations(d)
   events=self._events(d)
   events[1]["seq"]=99
   with self.assertRaises(ValueError):
    validate_history(events, d)

 def test_rejects_invalid_event_shape(self):
  with tempfile.TemporaryDirectory() as d:
   self._stream_with_observations(d)
   events=self._events(d)
   del events[0]["caused_by"]  # required envelope key
   with self.assertRaises(ValueError):
    validate_history(events, d)

 def test_rejects_noncanonical_typed_payload(self):
  with tempfile.TemporaryDirectory() as d:
   self._stream_with_observations(d)
   events=self._events(d)
   del events[0]["payload"]["subject"]
   with self.assertRaisesRegex(ValueError, "missing fields: subject"):
    validate_history(events, d)

 def test_rejects_tampered_quality_as_non_canonical(self):
  # Quality is re-derived from the evidence bytes; a peer that relabels a direct
  # observation as heuristic must be rejected as non-canonical, not trusted.
  with tempfile.TemporaryDirectory() as d:
   self._stream_with_observations(d)
   events=self._events(d)
   events[0]["payload"]["quality"]={"level":"heuristic"}
   with self.assertRaises(ValueError):
    validate_history(events, d)

 def test_rejects_evidence_absent_from_artifact_root(self):
  # Evidence must resolve against the importing side's artifact store; a digest
  # the local store cannot produce fails closed rather than being admitted.
  with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as empty:
   self._stream_with_observations(d)
   events=self._events(d)
   with self.assertRaises(ValueError):
    validate_history(events, empty, artifact_root=empty)

if __name__ == "__main__": unittest.main()
