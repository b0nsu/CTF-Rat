#!/usr/bin/env python3
"""Real Bubblewrap smoke: staged input -> isolated tool -> broker import."""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"bin"))
from ratlib.artifact import get, put_bytes
from ratlib.broker import run_task
from ratlib.orchestration import DEFAULT_BUDGET, enter, start_task

if not shutil.which("bwrap"):
 print("broker sandbox: SKIP (bwrap unavailable)")
 raise SystemExit(0)
probe=subprocess.run(["bwrap","--ro-bind","/","/","--","true"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if probe.returncode:
 print("broker sandbox: %s (bwrap unavailable to this user namespace)" % ("FAIL" if os.environ.get("RAT_REQUIRE_BWRAP")=="1" else "SKIP"))
 raise SystemExit(5 if os.environ.get("RAT_REQUIRE_BWRAP")=="1" else 0)

def contract():
 return {"schema":"rat.role-contract/v1","role":"orchestrator","phase":"solve-P0","objective":"sandbox smoke","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False,"tool_allowlist":["rat-profile"]},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}

with tempfile.TemporaryDirectory(dir=ROOT) as d:
 d=Path(d); (d/"run.json").write_text(json.dumps({"run_id":"sandbox-local"}))
 artifact=put_bytes(Path("/bin/true").read_bytes(),kind="challenge-binary",media_type="application/octet-stream",logical_name="true",root=d/".rat")
 cp=enter(str(d),"solve-P0"); c=contract(); c["allowed_inputs"]=[artifact["digest"]]
 task=start_task(str(d),c,checkpoint_id=cp["checkpoint_id"],inputs=[])
 result=run_task(str(d),task["task_id"],[str(ROOT/"bin/rat-profile"),"/ignored","--format","json"],inputs=[artifact["digest"]],bindings={1:artifact["digest"]},ctf_home=str(ROOT),wall_seconds=20)
 if result["exit_code"]:
  stderr=next(x["digest"] for x in result["artifacts"] if x["kind"]=="broker-stderr")
  raise AssertionError(get(stderr,root=d/".rat").decode(errors="replace"))
 assert result["receipt_digest"].startswith("sha256:")
 assert any(x["kind"]=="profile" for x in result["artifacts"]), result
 assert not any((d/".rat"/"execution").glob("broker-*"))
print("broker sandbox: PASS")
