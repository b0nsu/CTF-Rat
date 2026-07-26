#!/usr/bin/env python3
"""Real verifier report import and broker-side promotion deployment smoke."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOCKET=os.environ.get("RAT_BROKER_SOCKET")
if not SOCKET:
 print("broker verify: %s (RAT_BROKER_SOCKET is unset)" % ("FAIL" if os.environ.get("RAT_REQUIRE_BROKER_SOCKET")=="1" else "SKIP")); raise SystemExit(5 if os.environ.get("RAT_REQUIRE_BROKER_SOCKET")=="1" else 0)
sys.path.insert(0,str(ROOT/"bin"))
from ratlib.artifact import get, put_bytes
from ratlib.analysis import execution_environment
from ratlib.orchestration import DEFAULT_BUDGET, enter, finish_phase, finish_task, start_task
from ratlib.state_v2 import Stream, revise_primitive

def contract():
 return {"schema":"rat.role-contract/v1","role":"exploit-builder","phase":"solve-P4","objective":"verify smoke","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-verify"]},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def artifact(envelope, kind): return next(x["digest"] for x in envelope["artifacts"] if x["kind"]==kind)

# Production installs keep ROOT read-only; solve is the designated shared
# challenge-state location.
with tempfile.TemporaryDirectory(dir=ROOT/"solve") as raw:
 d=Path(raw); store=d/".rat"; (d/"run.json").write_text(json.dumps({"run_id":"verify-local"}))
 scenario=d/"scenario.json"; scenario.write_text(json.dumps({"schema":"rat.scenario/v1","expect":{"exit_code":0}}))
 profile=json.loads(subprocess.run([str(ROOT/"bin/rat-profile"),"/bin/true","--store",str(store),"--format","json"],text=True,capture_output=True,check=True).stdout)
 trace=json.loads(subprocess.run([str(ROOT/"bin/rat-dyn"),"/bin/true","--profile",artifact(profile,"profile"),"--scenario",str(scenario),"--store",str(store),"--format","json"],text=True,capture_output=True,check=True).stdout)
 binary=put_bytes(Path("/bin/true").read_bytes(),kind="challenge-binary",media_type="application/octet-stream",logical_name="true",root=store)
 environment=execution_environment(json.loads(get(artifact(profile,"profile"),root=store)),json.loads(scenario.read_text()))
 scenario_artifact=put_bytes(scenario.read_bytes(),kind="verification-scenario",media_type="application/json",logical_name="scenario.json",root=store)
 s=Stream(str(d))
 for oid in ("o1","o2","o3","obs"):
  evidence=put_bytes(oid.encode(),kind="self-evidence",media_type="text/plain",logical_name=oid,root=store,provenance={"evidence_policy":{"level":"direct","promotion_allowed":True}})
  s.append("observation.recorded",{"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[evidence["digest"]]})
 for phase in ("solve-P0","solve-P1","solve-P2"):
  enter(str(d),phase); finish_phase(str(d),phase)
 enter(str(d),"solve-P3")
 revise_primitive(s,{"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":binary["digest"],"environment_digest":environment})
 revise_primitive(s,{"primitive_id":"p","status":"pass","self_evidence":["o1","o2","o3"],"input_digest":binary["digest"],"environment_digest":environment})
 finish_phase(str(d),"solve-P3"); cp=enter(str(d),"solve-P4")
 c=contract(); c["allowed_inputs"]=[binary["digest"],artifact(profile,"profile"),artifact(trace,"execution-trace"),scenario_artifact["digest"]]
 task=start_task(str(d),c,checkpoint_id=cp["checkpoint_id"],inputs=[],primitive_id="p",input_digest=binary["digest"],environment_digest=environment)
 subprocess.run(["setfacl","-Rm","u:ratbroker:rwx",str(d)],check=True)
 subprocess.run(["find",str(d),"-type","d","-exec","setfacl","-m","d:u:ratbroker:rwx,d:u:ctfrat:rwx","{}","+"],check=True)
 cmd=[str(ROOT/"bin/rat-broker"),"--socket",SOCKET,"--root",str(d),"--task",task["task_id"],"--wall-seconds","20","--action","tool-run"]
 for digest in c["allowed_inputs"]: cmd += ["--input",digest]
 cmd += ["--bind","1="+binary["digest"],"--bind","7="+scenario_artifact["digest"],"--run",str(ROOT/"bin/rat-verify"),"/ignored","--profile",artifact(profile,"profile"),"--trace",artifact(trace,"execution-trace"),"--scenario","/scenario","--claim","claim","--primitive","p","--exploit-task",task["task_id"],"--runs","1","--format","json"]
 invoked=subprocess.run(cmd,text=True,capture_output=True,env=os.environ|{"RAT_BROKER_REQUIRE_SOCKET":"1"})
 if invoked.returncode: raise AssertionError(invoked.stderr)
 receipt=json.loads(invoked.stdout)
 if not receipt["verification_report_digest"]:
  from ratlib.artifact import get
  stderr=next(x["digest"] for x in receipt["artifacts"] if x["kind"]=="broker-stderr")
  raise AssertionError(get(stderr,root=store).decode(errors="replace"))
 finish_task(str(d),task["task_id"],"completed",{"schema":"rat.task-output/v1","task_id":task["task_id"],"status":"completed","outputs":{},"evidence_ids":["obs"]})
 promoted=subprocess.run([str(ROOT/"bin/rat-verify-promote"),"--socket",SOCKET,"--root",str(d),"--receipt",receipt["receipt_digest"],"--evidence","obs"],text=True,capture_output=True,env=os.environ|{"RAT_BROKER_REQUIRE_SOCKET":"1"})
 if promoted.returncode: raise AssertionError(promoted.stderr)
 assert json.loads(promoted.stdout)["report_digest"]==receipt["verification_report_digest"]
print("broker verify: PASS")
