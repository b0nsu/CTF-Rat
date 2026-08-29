#!/usr/bin/env python3
"""Deterministic P3 lifecycle checks, including a real cancelled child."""
import argparse, json, os, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))
from ratlib.orchestration import (DEFAULT_BUDGET, GateError, converge, enter,
 finish_phase, finish_task, invalidate, plan_fanout, record_verification,
 report_skeptic, start_task)
from ratlib.artifact import put_bytes
from ratlib.state_v2 import Stream, revise_primitive
from ratlib.analysis import VERIFY_BUILD_DIGEST
from tests.direct_evidence_helper import direct_evidence_envelope, CANONICAL_SUBJECT, CANONICAL_ENVIRONMENT
D="sha256:"+"a"*64
def contract(role, phase): return {"schema":"rat.role-contract/v1","role":role,"phase":phase,"objective":"probe","allowed_inputs":[],"required_outputs":[],"forbidden_actions":[],"state_write_scope":[],"capabilities":{"network_write":False,"repository_write":False,"evidence_promote":False},"budgets":dict(DEFAULT_BUDGET),"stop_conditions":["budget"]}
def output(t): return {"schema":"rat.task-output/v1","task_id":t["task_id"],"status":"completed","outputs":{},"evidence_ids":["obs"]}
def observation(stream, oid):
 digest=direct_evidence_envelope(root=stream.root,producer="gdbq",measurement=b"measurement:"+oid.encode(),summary=oid)
 return {"observation_id":oid,"quality":{"level":"direct"},"validity":{"state":"active"},"evidence":[digest]}
def verification_report(root, task_id, primitive_id="p", environment=CANONICAL_ENVIRONMENT):
 report={"schema":"rat.verification-report/v1","verdict":"pass","repetitions":1,"environment_match":True,"scope":"local-only","provenance":{"claim_id":"claim","primitive_id":primitive_id,"exploit_task_id":task_id,"trace_digest":D,"environment_digest":environment},"results":[{"conditions_met":True}],"producer":{"tool":"rat-verify","build_digest":VERIFY_BUILD_DIGEST}}
 return put_bytes(json.dumps(report).encode(),kind="verification-report",media_type="application/json",logical_name="verification.json",root=os.path.join(root,".rat"))["digest"]
def advance(d,p): enter(d,p); finish_phase(d,p)
def p2(d):
 advance(d,"solve-P0"); advance(d,"solve-P1")
 s=Stream(d)
 for oid in ("o1","o2","obs"): s.append("observation.recorded",observation(s,oid))
 return enter(d,"solve-P2")
def primitive(d):
 s=Stream(d)
 for oid in ("p1","p2","p3"): s.append("observation.recorded",observation(s,oid))
 revise_primitive(s,{"primitive_id":"p","status":"candidate","self_evidence":[],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT})
 revise_primitive(s,{"primitive_id":"p","status":"pass","self_evidence":["p1","p2","p3"],"input_digest":CANONICAL_SUBJECT,"environment_digest":CANONICAL_ENVIRONMENT})
def verified_pipeline(d, verdict):
 p2(d); finish_phase(d,"solve-P2"); enter(d,"solve-P3"); primitive(d); finish_phase(d,"solve-P3"); cp4=enter(d,"solve-P4")
 b=start_task(d,contract("exploit-builder","solve-P4"),checkpoint_id=cp4["checkpoint_id"],inputs=[],primitive_id="p",input_digest=CANONICAL_SUBJECT,environment_digest=CANONICAL_ENVIRONMENT); finish_task(d,b["task_id"],"completed",output(b)); record_verification(d,verification_report(d,b["task_id"]),["obs"]); finish_phase(d,"solve-P4"); cp5=enter(d,"solve-P5")
 s=start_task(d,contract("skeptic","solve-P5"),checkpoint_id=cp5["checkpoint_id"],inputs=[]); finish_task(d,s["task_id"],"completed",output(s)); report_skeptic(d,{"schema":"rat.skeptic-report/v1","report_id":"r","run_id":"local","task_id":s["task_id"],"exploit_task_id":b["task_id"],"verdict":verdict,"counterexamples":[],"affected_ids":[],"residual_risks":[]}); return d
p=argparse.ArgumentParser(); p.add_argument("--scenario",choices=["converge","invalidate-cancel","verified-only-exploit","skeptic-refute"],required=True); a=p.parse_args()
with tempfile.TemporaryDirectory() as d:
 if a.scenario=="converge":
  cp=p2(d); bs=[{"hypothesis_id":"h1","objective":"one","falsification":"no-one","evidence_ids":["o1"]},{"hypothesis_id":"h2","objective":"two","falsification":"no-two","evidence_ids":["o2"]}]; plan_fanout(d,bs,{"uncertainty_set":["h1","h2"],"evidence_ids":["o1","o2"]},{"remaining":80,"per_branch":20,"converge":20}); ts=[start_task(d,contract("hypothesis","solve-P2"),checkpoint_id=cp["checkpoint_id"],inputs=[x],dependencies=["o"+str(i+1)]) for i,x in enumerate(("one","two"))]
  for t in ts: finish_task(d,t["task_id"],"completed",output(t))
  assert converge(d,["h1"],["h2"],[],[{"evidence_ids":["o1"]}])["retained"]==["h1"]
 elif a.scenario=="invalidate-cancel":
  cp=p2(d); child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True); t=start_task(d,contract("hypothesis","solve-P2"),checkpoint_id=cp["checkpoint_id"],inputs=["one"],dependencies=["o1"],child_pid=child.pid); assert invalidate(d,["o1"],"refuted")["cancelled"]==[t["task_id"]]
  child.wait(timeout=3); assert child.poll() is not None
 elif a.scenario=="verified-only-exploit":
  p2(d); finish_phase(d,"solve-P2"); enter(d,"solve-P3"); primitive(d); finish_phase(d,"solve-P3"); cp=enter(d,"solve-P4")
  try: start_task(d,contract("exploit-builder","solve-P4"),checkpoint_id=cp["checkpoint_id"],inputs=[])
  except GateError: pass
  else: raise AssertionError("primitive provenance bypassed")
 else:
  verified_pipeline(d,"refute")
  try: finish_phase(d,"solve-P5",True)
  except GateError: pass
  else: raise AssertionError("refuted skeptic accepted")
print("orchestration %s: PASS" % a.scenario)
