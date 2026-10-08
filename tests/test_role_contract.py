import multiprocessing, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import DEFAULT_BUDGET, GateError, converge, enter, finish_phase, finish_task, plan_fanout, rollback, start_task, invalidate
from ratlib.artifact import put_bytes
from ratlib.state_v2 import Stream
from tests.direct_evidence_helper import direct_evidence_envelope
def contract(role, phase, required=()):
 return {"schema":"rat.role-contract/v1","role":role,"phase":phase,"objective":"x","allowed_inputs":[],"required_outputs":list(required),"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def _start_parallel(root, checkpoint_id, index, queue):
 try:
  task=start_task(root,contract("hypothesis","solve-P2"),checkpoint_id=checkpoint_id,inputs=["branch-%d" % index])
  queue.put(("ok",task["task_id"]))
 except GateError as exc:
  queue.put(("blocked",str(exc)))
def output(task, outputs=None): return {"schema":"rat.task-output/v1","task_id":task["task_id"],"status":"completed","outputs":outputs or {},"evidence_ids":["e0"]}
def observation(stream, oid):
 digest=direct_evidence_envelope(root=stream.root,producer="gdbq",measurement=b"measurement:"+oid.encode(),summary=oid)
 return {"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[digest]}
def to_p2(d):
 for p in ("solve-P0","solve-P1"):
  enter(d,p); finish_phase(d,p)
 s=Stream(d)
 for oid in ("e0","e1","e2"): s.append("observation.recorded",observation(s,oid))
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
 def test_output_rejects_unknown_or_invalidated_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   cp=to_p2(d); task=start_task(d,contract("hypothesis","solve-P2"),checkpoint_id=cp["checkpoint_id"],inputs=["one"],dependencies=["e0"])
   bad={"schema":"rat.task-output/v1","task_id":task["task_id"],"status":"completed","outputs":{},"evidence_ids":["missing"]}
   with self.assertRaises(GateError): finish_task(d,task["task_id"],"completed",bad)
 def test_rollback_does_not_reuse_prior_fanout_attempt(self):
  with tempfile.TemporaryDirectory() as d:
   to_p2(d)
   branches=[{"hypothesis_id":"h1","objective":"one","falsification":"not-one","evidence_ids":["e1"]},{"hypothesis_id":"h2","objective":"two","falsification":"not-two","evidence_ids":["e2"]}]
   plan_fanout(d,branches,{"uncertainty_set":["h1","h2"],"evidence_ids":["e0"]},{"remaining":100,"per_branch":20,"converge":20})
   finish_phase(d,"solve-P2"); enter(d,"solve-P3"); rollback(d,"solve-P2","restart",["e0"])
   with self.assertRaises(GateError): converge(d,["h1"],["h2"],[],[{"evidence_ids":["e1"]}])
 def test_multiprocess_task_cap_is_atomic(self):
  with tempfile.TemporaryDirectory() as d:
   cp=to_p2(d)
   branches=[{"hypothesis_id":"h%d" % n,"objective":"branch-%d" % n,"falsification":"not-%d" % n,"evidence_ids":["e0"]} for n in range(3)]
   plan_fanout(d,branches,{"uncertainty_set":["h0","h1","h2"],"evidence_ids":["e0"]},{"remaining":100,"per_branch":20,"converge":20})
   queue=multiprocessing.Queue(); workers=[multiprocessing.Process(target=_start_parallel,args=(d,cp["checkpoint_id"],n,queue)) for n in range(5)]
   for worker in workers: worker.start()
   for worker in workers: worker.join(5); self.assertFalse(worker.is_alive())
   results=[queue.get(timeout=1) for _ in workers]
   self.assertEqual(sum(kind=="ok" for kind,_ in results),3)
   self.assertEqual(sum(kind=="blocked" for kind,_ in results),2)
