import json, os, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.artifact import put_bytes
from ratlib.observe import materialize
from ratlib.receipt import sign as sign_receipt
from ratlib.orchestration import DEFAULT_BUDGET, GateError, enter, start_task
from ratlib.state_v2 import Stream

def contract():
 return {"schema":"rat.role-contract/v1","role":"orchestrator","phase":"solve-P0","objective":"observe","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def receipt(root, task, artifact, lease):
 doc={"schema":"rat.broker-receipt/v1","receipt_id":"receipt_"+lease,"task_id":task["task_id"],"checkpoint_id":task["checkpoint_id"],"phase_attempt_id":task["phase_attempt_id"],"lineage_id":task["lineage_id"],"lease_id":lease,"tool":{"name":"rat-verify","build_digest":"sha256:"+"a"*64},"inputs":[],"sandbox":{"network":"none"},"result":{"artifacts":[{"digest":artifact}],"exit_code":0,"timed_out":False,"duration_ms":1}}
 doc["signature"]=sign_receipt(os.path.join(root,".rat"),doc)
 return put_bytes(json.dumps(doc).encode(),kind="broker-receipt",media_type="application/json",logical_name="receipt.json",root=os.path.join(root,".rat"),provenance={"broker":True,"task_id":task["task_id"]})["digest"]

class ObserveTests(unittest.TestCase):
 def test_materializer_creates_distinct_direct_occurrences(self):
  with tempfile.TemporaryDirectory() as d:
   cp=enter(d,"solve-P0"); task=start_task(d,contract(),checkpoint_id=cp["checkpoint_id"],inputs=[])
   content=put_bytes(b"same execution output",kind="broker-stdout",media_type="text/plain",logical_name="stdout",root=os.path.join(d,".rat"))["digest"]
   one=materialize(d,receipt_digest=receipt(d,task,content,"one"),artifact_digest=content,subject="binary",kind="execution",value="ok")
   two=materialize(d,receipt_digest=receipt(d,task,content,"two"),artifact_digest=content,subject="binary",kind="execution",value="ok")
   self.assertEqual(one["quality"],"direct"); self.assertNotEqual(one["occurrence_digest"],two["occurrence_digest"])
   self.assertEqual(len(Stream(d).view()["observations"]),2)
 def test_materializer_rejects_untrusted_receipt(self):
  with tempfile.TemporaryDirectory() as d:
   cp=enter(d,"solve-P0"); task=start_task(d,contract(),checkpoint_id=cp["checkpoint_id"],inputs=[])
   content=put_bytes(b"x",kind="broker-stdout",media_type="text/plain",logical_name="stdout",root=os.path.join(d,".rat"))["digest"]
   good=receipt(d,task,content,"one")
   raw=json.loads(__import__("ratlib.artifact",fromlist=["get"]).get(good,root=os.path.join(d,".rat")))
   raw["receipt_id"]="receipt_forged"
   forged=put_bytes(json.dumps(raw).encode(),kind="broker-receipt",media_type="application/json",logical_name="forged.json",root=os.path.join(d,".rat"))["digest"]
   with self.assertRaisesRegex(GateError,"not written by the broker"):
    materialize(d,receipt_digest=forged,artifact_digest=content,subject="binary",kind="execution",value="ok")
 def test_receipt_key_must_be_private(self):
  with tempfile.TemporaryDirectory() as d:
   key=os.path.join(d,"public.key")
   with open(key,"wb") as out: out.write(b"x"*32)
   os.chmod(key,0o644)
   with patch.dict(os.environ,{"RAT_BROKER_KEY_PATH":key}):
    with self.assertRaisesRegex(ValueError,"group/world"):
     sign_receipt(d,{"schema":"rat.broker-receipt/v1"})
