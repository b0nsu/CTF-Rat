import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import put_bytes, get, verify
from ratlib.schema import validate, ValidationError
from ratlib.state_v2 import Stream, consume_primitive, migrate_v1, revise_finding, revise_primitive
from ratlib.cache import key
from ratlib.contracts import execute

D="sha256:"+"a"*64
def observation(stream, oid, level="direct"):
 rec=put_bytes(oid.encode(),kind="test-evidence",media_type="text/plain",logical_name=oid,root=stream.root)
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
 def test_v1_migration_materializes_legacy_events_without_promoting_pass(self):
  with tempfile.TemporaryDirectory() as d:
   with open(os.path.join(d,"STATE.jsonl"),"w",encoding="utf-8") as f:
    f.write('{"t":"ok","text":"legacy fact"}\n{"t":"primitive","name":"rip","status":"pass","evidence":"old note"}\n')
   self.assertEqual(migrate_v1(d)["mapped"],2)
   view=Stream(d).view()
   self.assertEqual(next(iter(view["findings"].values()))["state"],"supported")
   self.assertEqual(next(iter(view["primitives"].values()))["status"],"candidate")
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
   doc={"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":D,"environment_digest":D}
   revise_primitive(s,doc); revise_primitive(s,{**doc,"status":"pass","self_evidence":["o1","o2","o3"]})
   consume_primitive(s,"p",input_digest=D,environment_digest=D)
   self.assertEqual(s.view()["primitives"]["p"]["status"],"consumed")
if __name__ == "__main__": unittest.main()
