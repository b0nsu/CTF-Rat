import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import (DEFAULT_BUDGET, GateError, _state, enter, finish_phase,
    finish_task, record_verification, report_skeptic, rollback, start_task)
from ratlib.artifact import put_bytes
from ratlib.state_v2 import Stream, revise_primitive
from ratlib.analysis import VERIFY_BUILD_DIGEST
from tests.direct_evidence_helper import direct_evidence_envelope, CANONICAL_SUBJECT, CANONICAL_ENVIRONMENT
D="sha256:"+"a"*64
def contract(role, phase):
 return {"schema":"rat.role-contract/v1","role":role,"phase":phase,"objective":"test","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def output(task): return {"schema":"rat.task-output/v1","task_id":task["task_id"],"status":"completed","outputs":{},"evidence_ids":["obs"]}
def observation(stream, oid):
 digest=direct_evidence_envelope(root=stream.root,producer="gdbq",measurement=b"measurement:"+oid.encode(),summary=oid)
 return {"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[digest]}
def verification_report(root, *, verdict="pass", task_id="task", primitive_id="p", environment=CANONICAL_ENVIRONMENT):
 report={"schema":"rat.verification-report/v1","verdict":verdict,"repetitions":1,"environment_match":verdict=="pass","scope":"local-only","provenance":{"claim_id":"claim","primitive_id":primitive_id,"exploit_task_id":task_id,"trace_digest":D,"environment_digest":environment},"results":[{"conditions_met":verdict=="pass"}],"producer":{"tool":"rat-verify","build_digest":VERIFY_BUILD_DIGEST}}
 return put_bytes(json.dumps(report).encode(),kind="verification-report",media_type="application/json",logical_name="verification.json",root=os.path.join(root,".rat"))["digest"]
def advance(root, phase):
 cp=enter(root,phase); finish_phase(root,phase); return cp
class PhaseValidatorTests(unittest.TestCase):
 def passed_primitive(self, root):
  s=Stream(root)
  for oid in ("o1","o2","o3","obs"): s.append("observation.recorded",observation(s,oid))
  revise_primitive(s,{"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT})
  revise_primitive(s,{"primitive_id":"p","status":"pass","self_evidence":["o1","o2","o3"],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT})
 def to_p3(self, root):
  for phase in ("solve-P0","solve-P1","solve-P2"): advance(root,phase)
  return enter(root,"solve-P3")
 def test_phase_exit_is_required_and_primitive_gate(self):
  with tempfile.TemporaryDirectory() as d:
   enter(d,"solve-P0")
   with self.assertRaises(GateError): enter(d,"solve-P1")
   finish_phase(d,"solve-P0"); enter(d,"solve-P1"); finish_phase(d,"solve-P1"); enter(d,"solve-P2"); finish_phase(d,"solve-P2"); enter(d,"solve-P3"); finish_phase(d,"solve-P3")
   with self.assertRaises(GateError): enter(d,"solve-P4")
   self.passed_primitive(d); enter(d,"solve-P4")
 def test_rollback_is_explicit(self):
  with tempfile.TemporaryDirectory() as d:
   advance(d,"solve-P0"); enter(d,"solve-P1"); self.assertTrue(rollback(d,"solve-P0","bad evidence",["o"]))
   self.assertEqual(_state(d),"solve-P0")
   self.assertEqual(Stream(d).view()["observations"],{})
 def test_verified_solve_requires_real_linked_skeptic(self):
  with tempfile.TemporaryDirectory() as d:
   self.to_p3(d); self.passed_primitive(d); finish_phase(d,"solve-P3"); cp4=enter(d,"solve-P4")
   builder=start_task(d,contract("exploit-builder","solve-P4"),checkpoint_id=cp4["checkpoint_id"],inputs=[],primitive_id="p",input_digest=CANONICAL_SUBJECT,environment_digest=CANONICAL_ENVIRONMENT)
   finish_task(d,builder["task_id"],"completed",output(builder)); record_verification(d,verification_report(d,task_id=builder["task_id"]),["obs"]); finish_phase(d,"solve-P4"); cp5=enter(d,"solve-P5")
   with self.assertRaises(GateError): report_skeptic(d,{"schema":"rat.skeptic-report/v1","report_id":"r","run_id":"local","task_id":"fake","exploit_task_id":builder["task_id"],"verdict":"accept","counterexamples":[],"affected_ids":[],"residual_risks":[]})
   skeptic=start_task(d,contract("skeptic","solve-P5"),checkpoint_id=cp5["checkpoint_id"],inputs=[])
   finish_task(d,skeptic["task_id"],"completed",output(skeptic))
   report_skeptic(d,{"schema":"rat.skeptic-report/v1","report_id":"r","run_id":"local","task_id":skeptic["task_id"],"exploit_task_id":builder["task_id"],"verdict":"inconclusive","counterexamples":[],"affected_ids":[],"residual_risks":["x"]})
   with self.assertRaises(GateError): finish_phase(d,"solve-P5",True)
 def test_verification_promotion_requires_report_artifact(self):
  with tempfile.TemporaryDirectory() as d:
   self.to_p3(d); self.passed_primitive(d); finish_phase(d,"solve-P3"); cp4=enter(d,"solve-P4")
   builder=start_task(d,contract("exploit-builder","solve-P4"),checkpoint_id=cp4["checkpoint_id"],inputs=[],primitive_id="p",input_digest=CANONICAL_SUBJECT,environment_digest=CANONICAL_ENVIRONMENT)
   finish_task(d,builder["task_id"],"completed",output(builder))
   with self.assertRaises(GateError): record_verification(d,"pass",["obs"])
   bad=verification_report(d,task_id=builder["task_id"])
   self.assertTrue(record_verification(d,bad,["obs"])["report_digest"].startswith("sha256:"))
 def test_rollback_stales_prior_lineage_verification_and_exploit(self):
  with tempfile.TemporaryDirectory() as d:
   self.to_p3(d); self.passed_primitive(d); finish_phase(d,"solve-P3"); cp4=enter(d,"solve-P4")
   builder=start_task(d,contract("exploit-builder","solve-P4"),checkpoint_id=cp4["checkpoint_id"],inputs=[],primitive_id="p",input_digest=CANONICAL_SUBJECT,environment_digest=CANONICAL_ENVIRONMENT)
   finish_task(d,builder["task_id"],"completed",output(builder)); record_verification(d,verification_report(d,task_id=builder["task_id"]),["obs"]); finish_phase(d,"solve-P4"); enter(d,"solve-P5")
   rollback(d,"solve-P2","retry",["obs"])
   with open(os.path.join(d,".rat","tasks",builder["task_id"]+".json"),encoding="utf-8") as source: task=json.load(source)
   self.assertEqual(task["status"],"stale")
   self.assertTrue(any(e["type"]=="verification.staled" for e in Stream(d).read()))
   finish_phase(d,"solve-P2"); enter(d,"solve-P3"); finish_phase(d,"solve-P3"); enter(d,"solve-P4"); finish_phase(d,"solve-P4")
   with self.assertRaises(GateError): enter(d,"solve-P5")
