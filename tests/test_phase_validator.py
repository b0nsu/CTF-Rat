import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import (DEFAULT_BUDGET, GateError, _state, enter, finish_phase,
    finish_task, record_verification, report_skeptic, rollback, start_task)
from ratlib.state_v2 import Stream, revise_primitive
D="sha256:"+"a"*64
def contract(role, phase):
 return {"schema":"rat.role-contract/v1","role":role,"phase":phase,"objective":"test","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def output(task): return {"schema":"rat.task-output/v1","task_id":task["task_id"],"status":"completed","outputs":{},"evidence_ids":["obs"]}
def advance(root, phase):
 cp=enter(root,phase); finish_phase(root,phase); return cp
class PhaseValidatorTests(unittest.TestCase):
 def passed_primitive(self, root):
  s=Stream(root)
  for oid in ("o1","o2","o3"): s.append("observation.recorded",{"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"}})
  revise_primitive(s,{"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":D,"environment_digest":D})
  revise_primitive(s,{"primitive_id":"p","status":"pass","self_evidence":["o1","o2","o3"],"input_digest":D,"environment_digest":D})
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
   builder=start_task(d,contract("exploit-builder","solve-P4"),checkpoint_id=cp4["checkpoint_id"],inputs=[],primitive_id="p",input_digest=D,environment_digest=D)
   finish_task(d,builder["task_id"],"completed",output(builder)); record_verification(d,"pass",["obs"],True,exploit_task_id=builder["task_id"],primitive_id="p"); finish_phase(d,"solve-P4"); cp5=enter(d,"solve-P5")
   with self.assertRaises(GateError): report_skeptic(d,{"schema":"rat.skeptic-report/v1","report_id":"r","run_id":"local","task_id":"fake","exploit_task_id":builder["task_id"],"verdict":"accept","counterexamples":[],"affected_ids":[],"residual_risks":[]})
   skeptic=start_task(d,contract("skeptic","solve-P5"),checkpoint_id=cp5["checkpoint_id"],inputs=[])
   finish_task(d,skeptic["task_id"],"completed",output(skeptic))
   report_skeptic(d,{"schema":"rat.skeptic-report/v1","report_id":"r","run_id":"local","task_id":skeptic["task_id"],"exploit_task_id":builder["task_id"],"verdict":"inconclusive","counterexamples":[],"affected_ids":[],"residual_risks":["x"]})
   with self.assertRaises(GateError): finish_phase(d,"solve-P5",True)
