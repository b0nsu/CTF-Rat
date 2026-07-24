import os, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.artifact import put_bytes
from ratlib.broker import authorize, run_authorized
from ratlib.orchestration import DEFAULT_BUDGET, GateError
from ratlib.runner import CapturedStream, RunResult

def contract(**overrides):
 base={"schema":"rat.role-contract/v1","role":"hypothesis","phase":"solve-P2","objective":"test","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":["hypothesis.recorded"],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-profile"]},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
 base.update(overrides); return base

class BrokerTests(unittest.TestCase):
 def runner(self, argv, **kwargs):
  self.argv=argv
  empty=CapturedStream(b"",0,False,None)
  return RunResult(argv,0,0,False,False,1,empty,empty,"inherit",None,False,"test")
 def test_denies_ungranted_capabilities_and_state_scope(self):
  with self.assertRaises(GateError): authorize(contract(),"network-write")
  with self.assertRaises(GateError): authorize(contract(),"state-write",state_event="finding.revised")
  with self.assertRaises(GateError): authorize(contract(),"tool-run",tool="rat-rop")
 def test_accepts_allowlisted_existing_artifact_only(self):
  with tempfile.TemporaryDirectory() as d:
   artifact=put_bytes(b"e",kind="test",media_type="text/plain",logical_name="e",root=d)
   c=contract(allowed_inputs=[artifact["digest"]])
   result=authorize(c,"tool-run",tool="rat-profile",inputs=[artifact["digest"]],artifact_root=d)
   self.assertTrue(result["authorized"])
   with self.assertRaises(GateError): authorize(c,"tool-run",tool="rat-profile",inputs=["sha256:"+"0"*64],artifact_root=d)
 def test_binds_paths_to_artifacts_and_runs_inside_sandbox(self):
  with tempfile.TemporaryDirectory() as d:
   root=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
   binary=put_bytes(b"not an executable",kind="challenge-binary",media_type="application/octet-stream",logical_name="chall",root=d)
   c=contract(allowed_inputs=[binary["digest"]])
   with patch("ratlib.broker.run",self.runner):
    result=run_authorized(c,[os.path.join(root,"bin","rat-profile"),"--binary","/tmp/attacker"],inputs=[binary["digest"]],bindings={2:binary["digest"]},artifact_root=d,ctf_home=root,challenge_dir=root)
   self.assertTrue(result["authorized"]); self.assertIn("--unshare-net",self.argv); self.assertIn("--ro-bind",self.argv); self.assertIn(os.path.join(d,"materialized",binary["digest"][7:]),self.argv)
   with self.assertRaises(GateError): run_authorized(c,[os.path.join(root,"bin","rat-profile"),"--binary","/tmp/attacker"],inputs=[binary["digest"]],artifact_root=d,ctf_home=root,challenge_dir=root)
   with self.assertRaises(GateError): run_authorized(contract(),[sys.executable,"-c","pass"],artifact_root=d,ctf_home=root)
