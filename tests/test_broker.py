import os, sys, tempfile, threading, unittest, subprocess
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.artifact import put_bytes
from ratlib.broker import authorize, run_authorized, _network_policy
from ratlib.broker_service import request, serve
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
   with patch("ratlib.broker.run",self.runner), patch("ratlib.broker.shutil.which",return_value="/usr/bin/bwrap"):
    result=run_authorized(c,[os.path.join(root,"bin","rat-profile"),"--binary","/tmp/attacker"],inputs=[binary["digest"]],bindings={2:binary["digest"]},artifact_root=d,ctf_home=root,challenge_dir=root)
   self.assertTrue(result["authorized"]); self.assertIn("--unshare-net",self.argv); self.assertIn("--ro-bind",self.argv); self.assertIn("/rat-output/materialized/"+binary["digest"][7:],self.argv)
   self.assertNotIn(("--ro-bind",d,d),tuple(zip(self.argv,self.argv[1:],self.argv[2:])))
   with self.assertRaises(GateError): run_authorized(c,[os.path.join(root,"bin","rat-profile"),"--binary","/tmp/attacker"],inputs=[binary["digest"]],artifact_root=d,ctf_home=root,challenge_dir=root)
   with self.assertRaises(GateError): run_authorized(contract(),[sys.executable,"-c","pass"],artifact_root=d,ctf_home=root)
 def test_network_capability_never_falls_back_to_host_network(self):
  with tempfile.TemporaryDirectory() as d:
   root=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
   c=contract(role="primitive-verifier",phase="solve-P3",capabilities={"network_write":True,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-profile"]})
   with patch("ratlib.broker.shutil.which",return_value="/usr/bin/bwrap"):
    with self.assertRaisesRegex(GateError,"network task requires|target-filtered network"):
     run_authorized(c,[os.path.join(root,"bin","rat-profile")],artifact_root=d,ctf_home=root,challenge_dir=root)
 def test_network_adapter_receives_only_active_guard_target(self):
  repo=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
  with tempfile.TemporaryDirectory(dir=repo) as home:
   os.mkdir(os.path.join(home,"bin")); os.mkdir(os.path.join(home,"solve")); challenge=os.path.join(home,"solve","demo"); os.mkdir(challenge)
   os.symlink(os.path.join(repo,"bin","rat-profile"),os.path.join(home,"bin","rat-profile"))
   with open(os.path.join(home,"ACTIVE.json"),"w",encoding="utf-8") as out: __import__("json").dump({"chal":"demo","targets":["example.test:31337"]},out)
   with open(os.path.join(challenge,"run.json"),"w",encoding="utf-8") as out: __import__("json").dump({"target_policy":{"guard_challenge":"demo","allowlist":["example.test:31337"],"network_mode":"ctfguard-target"}},out)
   c=contract(role="primitive-verifier",phase="solve-P3",capabilities={"network_write":True,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-profile"]})
   with patch.dict(os.environ,{"RAT_BROKER_NETWORK_RUNNER":"/bin/true"}), patch("ratlib.broker.run",self.runner), patch("ratlib.broker.shutil.which",return_value="/usr/bin/bwrap"), patch("ratlib.broker.socket.getaddrinfo",return_value=[(2,1,6,"",("203.0.113.7",0))]):
    result=run_authorized(c,[os.path.join(home,"bin","rat-profile")],artifact_root=os.path.join(challenge,".rat"),ctf_home=home,challenge_dir=challenge)
   self.assertEqual(result["sandbox"]["network"],{"host":"example.test","port":31337,"target":"example.test:31337"})
   self.assertEqual(self.argv[0],"/bin/true"); self.assertIn("--allow-host",self.argv); self.assertIn("example.test",self.argv); self.assertIn("31337",self.argv)
 def test_network_policy_uses_runtime_active_lock(self):
  repo=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
  with tempfile.TemporaryDirectory(dir=repo) as home, tempfile.TemporaryDirectory() as runtime:
   challenge=os.path.join(home,"solve","demo"); os.makedirs(challenge)
   with open(os.path.join(runtime,"ACTIVE.json"),"w",encoding="utf-8") as out: __import__("json").dump({"chal":"demo","targets":["example.test:31337"]},out)
   with open(os.path.join(challenge,"run.json"),"w",encoding="utf-8") as out: __import__("json").dump({"target_policy":{"guard_challenge":"demo","allowlist":["example.test:31337"],"network_mode":"ctfguard-target"}},out)
   with patch.dict(os.environ,{"RAT_RUNTIME_DIR":runtime},clear=False):
    self.assertEqual(_network_policy(challenge,home),{"host":"example.test","port":31337,"target":"example.test:31337"})
 def test_network_sandbox_pins_hostname_hosts_file(self):
  from ratlib.broker import _sandbox_argv
  with tempfile.TemporaryDirectory() as d:
   root=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
   with patch("ratlib.broker.shutil.which",return_value="/usr/bin/bwrap"), patch("ratlib.broker.socket.getaddrinfo",return_value=[(2,1,6,"",("203.0.113.7",0))]), patch.dict(os.environ,{"RAT_BROKER_NETWORK_RUNNER":"/bin/true"},clear=False):
    command=_sandbox_argv(["/bin/true"],root=d,ctf_home=root,challenge_dir=root,network_write=True,output_dir=d,network_policy={"host":"example.test","port":31337,"target":"example.test:31337"})
   self.assertIn("/etc/hosts",command)
   with open(os.path.join(d,"pinned-hosts")) as source: hosts=source.read()
   self.assertIn("203.0.113.7 example.test",hosts)
 def test_privileged_socket_broker_checks_peer_and_returns_result(self):
  home=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
  with tempfile.TemporaryDirectory(dir=home) as d:
   path=os.path.join(d,"broker.sock")
   with patch("ratlib.broker_service.run_task",return_value={"receipt_digest":"sha256:"+"a"*64}) as run:
    worker=threading.Thread(target=serve,args=(path,),kwargs={"allowed_uid":os.getuid(),"ctf_home":home,"once":True},daemon=True); worker.start()
    for _ in range(100):
     if os.path.exists(path): break
     __import__("time").sleep(.01)
    for _ in range(100):
     try:
      response=request(path,{"task_id":"task","root":d,"argv":["x"],"inputs":[],"bindings":{},"wall_seconds":1}); break
     except GateError: __import__("time").sleep(.01)
    else: self.fail("broker service did not accept a connection")
    self.assertEqual(response["receipt_digest"],"sha256:"+"a"*64)
    worker.join(timeout=1); self.assertFalse(worker.is_alive()); run.assert_called_once()
 def test_broker_imports_verifier_output_and_links_report(self):
  with tempfile.TemporaryDirectory() as d:
   repo=os.path.abspath(os.path.join(os.path.dirname(__file__),".."))
   report=put_bytes(b'{"schema":"rat.verification-report/v1"}',kind="verification-report",media_type="application/json",logical_name="verification.json",root=d)
   # The mock places the report into the ephemeral sandbox store; the broker
   # must import it into the durable store and discover it from stdout.
   def verifier(argv, **kwargs):
    staged=put_bytes(b'{"schema":"rat.verification-report/v1"}',kind="verification-report",media_type="application/json",logical_name="verification.json",root=kwargs["spool_dir"])
    envelope=__import__("json").dumps({"schema":"rat.tool-result/v1","artifacts":[{"kind":"verification-report","digest":staged["digest"]}]}).encode()
    stream=CapturedStream(envelope,len(envelope),False,None)
    return RunResult(argv,0,0,False,False,1,stream,CapturedStream(b"",0,False,None),"none",None,False,"test")
   c=contract(role="primitive-verifier",phase="solve-P3",capabilities={"network_write":False,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-verify"]})
   with patch("ratlib.broker.run",verifier), patch("ratlib.broker.shutil.which",return_value="/usr/bin/bwrap"):
    result=run_authorized(c,[os.path.join(repo,"bin","rat-verify")],artifact_root=d,ctf_home=repo,challenge_dir=repo)
   self.assertEqual(result["verification_report_digest"],report["digest"])
   self.assertTrue(any(x["digest"]==report["digest"] and x["kind"]=="verification-report" for x in result["artifacts"]))
 def test_production_mode_rejects_direct_cli(self):
  tool=os.path.join(os.path.dirname(__file__),"..","bin","rat-broker")
  result=subprocess.run([tool,"--task","task","--action","tool-run","--run","x"],text=True,capture_output=True,env=os.environ|{"RAT_BROKER_REQUIRE_SOCKET":"1"})
  self.assertEqual(result.returncode,5); self.assertIn("requires --socket",result.stderr)
