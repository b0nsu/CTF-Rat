import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import DEFAULT_BUDGET, GateError, enter, finish_phase, finish_task, plan_fanout, start_task, invalidate
def contract(role, phase, required=()):
 return {"schema":"rat.role-contract/v1","role":role,"phase":phase,"objective":"x","allowed_inputs":[],"required_outputs":list(required),"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def output(task, outputs=None): return {"schema":"rat.task-output/v1","task_id":task["task_id"],"status":"completed","outputs":outputs or {},"evidence_ids":["o"]}
def to_p2(d):
 for p in ("solve-P0","solve-P1"):
  enter(d,p); finish_phase(d,p)
 return enter(d,"solve-P2")
class RoleContractTests(unittest.TestCase):
 def test_p2_single_branch_and_cap_and_invalidation_cancel(self):
  with tempfile.TemporaryDirectory() as d:
   cp=to_p2(d)
   one=start_task(d,contract("hypothesis","solve-P2"),checkpoint_id=cp["checkpoint_id"],inputs=["one"],dependencies=["e0"])
   finish_task(d,one["task_id"],"completed",output(one))
   branches=[{"hypothesis_id":"h%d"%n,"objective":"o%d"%n,"falsification":"f%d"%n,"evidence_ids":["e%d"%n]} for n in range(3)]
   plan_fanout(d,branches,{"uncertainty_set":["h0","h1","h2"],"evidence_ids":["e0"]},{"remaining":100,"per_branch":20,"converge":20})
   tasks=[start_task(d,contract("hypothesis","solve-P2"),checkpoint_id=cp["checkpoint_id"],inputs=[str(n)],dependencies=["e%d"%n]) for n in range(3)]
   with self.assertRaises(GateError): start_task(d,contract("hypothesis","solve-P2"),checkpoint_id=cp["checkpoint_id"],inputs=["4"])
   self.assertEqual(invalidate(d,["e1"],"contradicted")["cancelled"],[tasks[1]["task_id"]])
 def test_forbidden_phase_fanout_and_role_phase_contract(self):
  with tempfile.TemporaryDirectory() as d:
   cp=enter(d,"solve-P0"); start_task(d,contract("orchestrator","solve-P0"),checkpoint_id=cp["checkpoint_id"],inputs=[])
   with self.assertRaises(GateError): start_task(d,contract("orchestrator","solve-P0"),checkpoint_id=cp["checkpoint_id"],inputs=[])
   with self.assertRaises(GateError): start_task(d,contract("hypothesis","solve-P0"),checkpoint_id=cp["checkpoint_id"],inputs=[])
 def test_invalid_output_is_quarantined_then_repaired_once(self):
  with tempfile.TemporaryDirectory() as d:
   cp=enter(d,"solve-P0"); task=start_task(d,contract("orchestrator","solve-P0",["finding"]),checkpoint_id=cp["checkpoint_id"],inputs=[])
   with self.assertRaises(GateError): finish_task(d,task["task_id"],"completed",{})
   with self.assertRaises(GateError): finish_task(d,task["task_id"],"completed",output(task))
