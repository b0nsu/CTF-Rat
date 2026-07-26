import json, os, pathlib, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import put_bytes, get, verify
from ratlib.schema import validate, ValidationError
from ratlib.state_v2 import Stream, consume_primitive, migrate_v1, revise_finding, revise_primitive
from ratlib.cache import key
from ratlib.contracts import execute

D="sha256:"+"a"*64
def observation(stream, oid, level="direct"):
 rec=put_bytes(oid.encode(),kind="test-evidence",media_type="text/plain",logical_name=oid,root=stream.root,provenance={"evidence_policy":{"level":level,"promotion_allowed":level=="direct"}})
 return {"observation_id":oid,"quality":{"level":level},"validity":{"state":"active"},"evidence":[rec["digest"]]}
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
   p={"primitive_id":"p","status":"candidate","self_evidence":[]}
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
 def test_stream_append_cannot_bypass_finding_or_primitive_lifecycle(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d); s.append("observation.recorded",observation(s,"o"))
   with self.assertRaises(ValueError): s.append("finding.revised",{"finding_id":"f","state":"confirmed","evidence_observation_ids":["o"]})
   with self.assertRaises(ValueError): s.append("primitive.revised",{"primitive_id":"p","status":"pass","self_evidence":["o","o","o"]})
 def test_evidence_quality_is_derived_from_artifact_policy(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   artifact=put_bytes(b"p2",kind="rat-profile",media_type="application/json",logical_name="result.json",root=s.root,provenance={"evidence_policy":{"level":"heuristic","promotion_allowed":False}})
   s.append("observation.recorded",{"observation_id":"p2","quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[artifact["digest"]]})
   self.assertEqual(s.view()["observations"]["p2"]["quality"]["level"],"heuristic")
   with self.assertRaises(ValueError): revise_finding(s,{"finding_id":"f","state":"confirmed","evidence_observation_ids":["p2"]})
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
 def test_legacy_state_write_is_rejected_after_v2_migration(self):
  with tempfile.TemporaryDirectory() as d:
   pathlib.Path(d,"STATE.jsonl").write_text('{"t":"hypothesis","text":"legacy"}\n')
   migrate_v1(d)
   tool=os.path.join(os.path.dirname(__file__),"..","bin","state")
   result=subprocess.run([tool,"--dir",d,"note","would fork state"],text=True,capture_output=True)
   self.assertEqual(result.returncode,2); self.assertIn("disabled after v2 migration",result.stderr)
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
 def test_checkpoint_is_bounded_and_atomically_serialized(self):
  with tempfile.TemporaryDirectory() as d:
   s=Stream(d)
   for n in range(100): s.append("note.recorded",{"note_id":"n%d" % n,"text":"x"*200})
   cp=s.checkpoint(phase="P1",task_id="a",role="scout",reason="bounded",max_bytes=4096)
   path=os.path.join(d,".rat","checkpoints",cp["checkpoint_id"]+".json")
   self.assertLessEqual(os.path.getsize(path),4096)
   with open(path,encoding="utf-8") as source: restored=json.load(source)
   self.assertEqual(restored["checkpoint_id"],cp["checkpoint_id"])
   self.assertTrue("overflow_artifact" in restored or "overflow_artifact" in json.loads(get(cp["context_artifact"],root=os.path.join(d,".rat"))))
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
   doc={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":D,"environment_digest":D}
   revise_primitive(s,doc); revise_primitive(s,{**doc,"status":"pass","self_evidence":["o1","o2","o3"]})
   consume_primitive(s,"p",input_digest=D,environment_digest=D)
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
if __name__ == "__main__": unittest.main()
