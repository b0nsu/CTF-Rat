import json, os, pathlib, shutil, subprocess, sys, tempfile, unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=ROOT/"bin"; FIX=ROOT/"tests"/"fixtures"/"analysis"
sys.path.insert(0,str(BIN))
from ratlib.schema import validate

@unittest.skipUnless(shutil.which("gcc"), "gcc required for executable P2 fixture")
class P2Analysis(unittest.TestCase):
 def setUp(self):
  self.d=tempfile.TemporaryDirectory(); self.work=pathlib.Path(self.d.name); self.exe=self.work/"toy"
  subprocess.run(["gcc","-O0","-fno-pie","-no-pie",str(FIX/"toy.c"),"-o",str(self.exe)],check=True)
  self.sc=self.work/"scenario.json"; self.sc.write_bytes((FIX/"success.scenario.json").read_bytes()); self.store=self.work/"store"
 def tearDown(self): self.d.cleanup()
 def tool(self,name,*args,ok=True):
  p=subprocess.run([str(BIN/name),str(self.exe),"--store",str(self.store),"--format","json",*args],text=True,capture_output=True)
  if ok: self.assertEqual(p.returncode,0,p.stderr)
  doc=json.loads(p.stdout); validate(doc, "rat.tool-result/v1"); return p, doc
 def test_core_profile_slice_dyn_verify(self):
  _,x=self.tool("rat-profile"); self.assertEqual(x["schema"],"rat.tool-result/v1"); self.assertGreater(x["summary"]["fact_count"],0); profile=x["artifacts"][0]["digest"]
  self.assertEqual(x["extensions"]["analysis_policy"]["maturity"],"experimental")
  self.assertFalse(x["extensions"]["analysis_policy"]["promotion_allowed"])
  _,x=self.tool("rat-slice","--profile",profile,"--from","main","--to","fgets"); self.assertIn(x["status"],("ok","partial")); self.assertEqual(x["summary"]["analysis_kind"],"call-path")
  _,x=self.tool("rat-dyn","--profile",profile,"--scenario",str(self.sc)); self.assertEqual(x["summary"]["exit"],0); trace=x["artifacts"][0]["digest"]
  _,x=self.tool("rat-verify","--profile",profile,"--trace",trace,"--scenario",str(self.sc),"--claim","claim","--primitive","primitive","--exploit-task","task","--runs","3"); self.assertEqual(x["summary"]["verdict"],"pass")
  changed=self.work/"changed-env.json"; changed.write_text(json.dumps({"schema":"rat.scenario/v1","stdin":"OPEN\\n","env":{"RAT_VERIFY_TEST":"changed"},"expect":{"exit_code":0}}))
  p,x=self.tool("rat-verify","--profile",profile,"--trace",trace,"--scenario",str(changed),"--claim","claim","--primitive","primitive","--exploit-task","task",ok=False)
  self.assertEqual(p.returncode,124); self.assertEqual(x["summary"]["verdict"],"inconclusive"); self.assertFalse(x["summary"]["environment_match"])
 def test_profile_does_not_claim_elf_protections_for_non_elf(self):
  non_elf=self.work/"sample.pe"; non_elf.write_bytes(b"MZ"+b"\0"*126)
  p=subprocess.run([str(BIN/"rat-profile"),str(non_elf),"--store",str(self.store),"--format","json"],text=True,capture_output=True,check=True)
  result=json.loads(p.stdout); profile=json.loads(__import__("ratlib.artifact",fromlist=["get"]).get(result["artifacts"][0]["digest"],root=str(self.store)))
  self.assertEqual([fact["kind"] for fact in profile["facts"]],["format"])
  self.assertIn("ELF protection facts skipped",result["summary"]["coverage"])
 def test_verify_rejects_empty_expect_without_oracle(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  empty=self.work/"empty.json"; empty.write_text(json.dumps({"schema":"rat.scenario/v1","stdin":"OK\n"}))
  _,dyn=self.tool("rat-dyn","--profile",pd,"--scenario",str(empty)); trace=dyn["artifacts"][0]["digest"]
  p,doc=self.tool("rat-verify","--profile",pd,"--trace",trace,"--scenario",str(empty),"--claim","claim","--primitive","primitive","--exploit-task","task",ok=False)
  self.assertEqual(p.returncode,5); self.assertEqual(doc["status"],"error")
 def test_verify_oracle_is_required_and_recorded(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  empty=self.work/"empty.json"; empty.write_text(json.dumps({"schema":"rat.scenario/v1","stdin":"OK\n"}))
  _,dyn=self.tool("rat-dyn","--profile",pd,"--scenario",str(empty)); trace=dyn["artifacts"][0]["digest"]
  oracle=self.work/"oracle"; oracle.write_text("#!/bin/sh\nexit 0\n"); oracle.chmod(0o755)
  _,doc=self.tool("rat-verify","--profile",pd,"--trace",trace,"--scenario",str(empty),"--claim","claim","--primitive","primitive","--exploit-task","task","--oracle",str(oracle))
  self.assertEqual(doc["summary"]["verdict"],"pass")
  report=json.loads(__import__("ratlib.artifact",fromlist=["get"]).get(doc["artifacts"][0]["digest"],root=str(self.store)))
  self.assertTrue(report["results"][0]["oracle"]["artifact"].startswith("sha256:"))
  oracle.write_text("#!/bin/sh\nexit 1\n"); oracle.chmod(0o755)
  p,doc=self.tool("rat-verify","--profile",pd,"--trace",trace,"--scenario",str(empty),"--claim","claim","--primitive","primitive","--exploit-task","task","--oracle",str(oracle),ok=False)
  self.assertEqual(p.returncode,1); self.assertEqual(doc["summary"]["verdict"],"fail")
 def test_extensions_and_verified_only_rop_gate(self):
  _,x=self.tool("rat-fuzz","--budget","0.05"); self.assertGreater(x["summary"]["execs"],0)
  trace=self.work/"heap.json"; trace.write_text(json.dumps({"allocator":"glibc","events":[{"chunk":4096,"target":8192,"encoded_fd":8193}]}))
  _,x=self.tool("rat-heap","--trace",str(trace)); self.assertEqual(x["summary"]["invariant_violations"],[])
  p,x=self.tool("rat-rop","--goal","call","--primitive","not-a-pass",ok=False); self.assertEqual(p.returncode,5); self.assertEqual(x["status"],"error")
  p,x=self.tool("rat-rop","--goal","call",ok=False); self.assertEqual(p.returncode,5); self.assertEqual(x["status"],"error")
  _,x=self.tool("rat-rop","--index-only"); self.assertTrue(x["summary"]["index_only"])
  _,x=self.tool("rat-runtime","--backend","native","--scenario",str(self.sc)); self.assertEqual(x["summary"]["exit"],0)
  _,x=self.tool("rat-runtime","--backend","qemu","--scenario",str(self.sc))
  if x["status"]=="partial": self.assertIn("unsupported",x["summary"])
  else: self.assertEqual(x["summary"]["exit"],0)
  _,x=self.tool("rat-runtime","--backend","qiling","--scenario",str(self.sc)); self.assertEqual(x["status"],"partial")
  bc=self.work/"vm.bin"; bc.write_bytes(bytes([2,1,0x10,3,5,0x51,255]))
  _,x=self.tool("rat-vm","--bytecode",str(bc),"--solve"); self.assertEqual(x["summary"]["unknown_opcode"],[])
  empty_oracle=self.work/"vm-empty-oracle.json"; empty_oracle.write_text(json.dumps({"schema":"rat.scenario/v1"}))
  _,x=self.tool("rat-vm","--bytecode",str(bc),"--solve","--oracle",str(empty_oracle)); self.assertEqual(x["summary"]["solve_candidates"],[]); self.assertEqual(x["status"],"partial")
 def test_pipeline_rejects_missing_or_mismatched_evidence_and_timeout(self):
  p=subprocess.run([str(BIN/"rat-dyn"),str(self.exe),"--store",str(self.store),"--format","json","--scenario",str(self.sc)],text=True,capture_output=True)
  self.assertEqual(p.returncode,2) # parser enforces the profile gate
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  slow=self.work/"slow.json"; slow.write_text(json.dumps({"schema":"rat.scenario/v1","stdin":"SLEEP\n"}))
  p,dyn=self.tool("rat-dyn","--profile",pd,"--scenario",str(slow),"--timeout","0.05",ok=False); self.assertEqual(p.returncode,124)
  self.assertEqual(dyn["status"],"timeout")
 def _symbol_addr(self,name):
  out=subprocess.run(["nm",str(self.exe)],text=True,capture_output=True,check=True).stdout
  for line in out.splitlines():
   parts=line.split()
   if len(parts)==3 and parts[2]==name: return "0x"+parts[0]
  return None
 def test_data_slice_finds_input_api_and_reports_dependency_candidate(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  main_addr=self._symbol_addr("main")
  if main_addr is None: self.skipTest("nm could not resolve main's address")
  _,x=self.tool("rat-slice","--profile",pd,"--mode","data","--backward",main_addr,"--source","stdin","--depth","2")
  self.assertEqual(x["summary"]["analysis_kind"],"data"); self.assertEqual(x["summary"]["claim"],"dependency-candidate")
  self.assertIn(x["status"],("ok","partial"))
  if x["status"]=="ok":
   self.assertIn("fgets",x["summary"]["within_function"]["input_api_calls"])
   self.assertLessEqual(x["summary"]["interproc"]["depth"],2)
 def test_data_slice_depth_budget_never_exceeds_two(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  main_addr=self._symbol_addr("main")
  if main_addr is None: self.skipTest("nm could not resolve main's address")
  _,x=self.tool("rat-slice","--profile",pd,"--mode","data","--backward",main_addr,"--source","stdin","--depth","50")
  if x["status"]=="ok":
   self.assertLessEqual(x["summary"]["interproc"]["depth"],2)
   self.assertTrue(set(x["summary"]["interproc"]["callers_by_depth"]).issubset({"1","2"}))
 def test_data_slice_never_promotes_to_proof_when_unresolved(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  main_addr=self._symbol_addr("main")
  if main_addr is None: self.skipTest("nm could not resolve main's address")
  _,x=self.tool("rat-slice","--profile",pd,"--mode","data","--backward",main_addr,"--source","stdin")
  if x["status"]=="ok":
   self.assertEqual(x["summary"]["claim"],"dependency-candidate")
   self.assertIn("unresolved_aliases",x["summary"]); self.assertIn("unresolved_indirect_calls",x["summary"])
 def test_data_slice_missing_address_is_input_error(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  p,x=self.tool("rat-slice","--profile",pd,"--mode","data","--backward","not-an-address","--source","stdin",ok=False)
  self.assertEqual(p.returncode,4); self.assertEqual(x["status"],"error")
 def test_data_slice_unresolved_target_address_is_partial(self):
  _,profile=self.tool("rat-profile"); pd=profile["artifacts"][0]["digest"]
  _,x=self.tool("rat-slice","--profile",pd,"--mode","data","--backward","0xdeadbeef","--source","stdin")
  self.assertEqual(x["status"],"partial")
if __name__=="__main__": unittest.main()
