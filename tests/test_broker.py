import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.artifact import put_bytes
from ratlib.broker import authorize, run_authorized
from ratlib.orchestration import DEFAULT_BUDGET, GateError

def contract(**overrides):
 base={"schema":"rat.role-contract/v1","role":"hypothesis","phase":"solve-P2","objective":"test","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":["hypothesis.recorded"],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-profile"]},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
 base.update(overrides); return base

class BrokerTests(unittest.TestCase):
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
 def test_runs_only_pinned_allowlisted_ctf_rat_tool(self):
  with tempfile.TemporaryDirectory() as d:
   root=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
   result=run_authorized(contract(),[os.path.join(root,"bin","rat-profile"),"--help"],artifact_root=d,ctf_home=root)
   self.assertTrue(result["authorized"]); self.assertEqual(result["exit_code"],0); self.assertEqual(len(result["artifacts"]),2)
   with self.assertRaises(GateError): run_authorized(contract(),[sys.executable,"-c","pass"],artifact_root=d,ctf_home=root)
