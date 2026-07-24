import os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import DEFAULT_BUDGET, enter, finish_phase, invalidate, start_task
from ratlib.artifact import put_bytes
from ratlib.state_v2 import Stream
def contract(): return {"schema":"rat.role-contract/v1","role":"hypothesis","phase":"solve-P2","objective":"cancel","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
class EarlyCancelTests(unittest.TestCase):
 def test_invalidation_terminates_registered_process_group(self):
  with tempfile.TemporaryDirectory() as d:
   enter(d,"solve-P0"); finish_phase(d,"solve-P0"); enter(d,"solve-P1"); finish_phase(d,"solve-P1"); cp=enter(d,"solve-P2")
   stream=Stream(d); evidence=put_bytes(b"e",kind="test-evidence",media_type="text/plain",logical_name="e",root=stream.root)
   stream.append("observation.recorded",{"observation_id":"e","quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[evidence["digest"]]})
   child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True)
   self.addCleanup(lambda: child.poll() is None and child.kill())
   task=start_task(d,contract(),checkpoint_id=cp["checkpoint_id"],inputs=["x"],dependencies=["e"],child_pid=child.pid)
   invalidate(d,["e"],"bad evidence"); child.wait(timeout=3)
   self.assertIsNotNone(child.poll())
