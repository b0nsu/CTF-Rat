#!/usr/bin/env python3
"""Optional deployment smoke for agent -> broker socket -> Bubblewrap."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOCKET=os.environ.get("RAT_BROKER_SOCKET")
if not SOCKET:
 print("broker socket: %s (RAT_BROKER_SOCKET is unset)" % ("FAIL" if os.environ.get("RAT_REQUIRE_BROKER_SOCKET")=="1" else "SKIP"))
 raise SystemExit(5 if os.environ.get("RAT_REQUIRE_BROKER_SOCKET")=="1" else 0)
if not os.path.exists(SOCKET) or not shutil.which("setfacl"):
 print("broker socket: FAIL (configured socket or setfacl unavailable)")
 raise SystemExit(5)
sys.path.insert(0,str(ROOT/"bin"))
from ratlib.artifact import put_bytes
from ratlib.orchestration import DEFAULT_BUDGET, enter, start_task

def contract():
 return {"schema":"rat.role-contract/v1","role":"orchestrator","phase":"solve-P0","objective":"socket sandbox smoke","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-profile"]},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}

# Production installs keep ROOT read-only; solve is the designated shared
# challenge-state location.
with tempfile.TemporaryDirectory(dir=ROOT/"solve",ignore_cleanup_errors=True) as d:
 d=Path(d); (d/"run.json").write_text(json.dumps({"run_id":"socket-local"}))
 artifact=put_bytes(Path("/bin/true").read_bytes(),kind="challenge-binary",media_type="application/octet-stream",logical_name="true",root=d/".rat")
 cp=enter(str(d),"solve-P0"); c=contract(); c["allowed_inputs"]=[artifact["digest"]]
 task=start_task(str(d),c,checkpoint_id=cp["checkpoint_id"],inputs=[])
 # The agent owns task creation; the separate broker gets explicit ACL access
 # only to this disposable challenge state for the integration probe.
 subprocess.run(["setfacl","-Rm","u:ratbroker:rwx",str(d)],check=True)
 subprocess.run(["find",str(d),"-type","d","-exec","setfacl","-m","d:u:ratbroker:rwx,d:u:ctfrat:rwx","{}","+"],check=True)
 cmd=[str(ROOT/"bin/rat-broker"),"--socket",SOCKET,"--root",str(d),"--task",task["task_id"],"--wall-seconds","20","--action","tool-run","--input",artifact["digest"],"--bind","1="+artifact["digest"],"--run",str(ROOT/"bin/rat-profile"),"/ignored","--format","json"]
 result=subprocess.run(cmd,text=True,capture_output=True,env=os.environ|{"RAT_BROKER_REQUIRE_SOCKET":"1"})
 if result.returncode: raise AssertionError(result.stderr)
 out=json.loads(result.stdout)
 assert out["exit_code"]==0 and out["receipt_digest"].startswith("sha256:"), out
 assert any(x["kind"]=="profile" for x in out["artifacts"]), out
print("broker socket: PASS")
