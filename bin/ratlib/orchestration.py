"""Fail-closed, transport-neutral P3 orchestration gates.

Tasks are durable records.  A transport may be absent (sequential fallback),
but when it starts a child it must register the child's process-group leader so
invalidation can terminate real work instead of merely changing a JSON status.
"""
from __future__ import annotations
import contextlib, fcntl, functools, json, os, signal, threading, time, uuid
from datetime import datetime, timezone
from typing import Any

from .artifact import get, put_bytes
from .receipt import verify as verify_receipt
from .state_v2 import Stream

PHASES = tuple("solve-P%d" % n for n in range(6))
ROLES = {"orchestrator", "static-scout", "dynamic-scout", "hypothesis",
         "primitive-verifier", "exploit-builder", "skeptic"}
ROLE_PHASES = {
    "orchestrator": {"solve-P0", "solve-P1", "solve-P2", "solve-P3"},
    "static-scout": {"solve-P1"}, "dynamic-scout": {"solve-P1"},
    "hypothesis": {"solve-P2"}, "primitive-verifier": {"solve-P3"},
    "exploit-builder": {"solve-P4"}, "skeptic": {"solve-P5"},
}
TERMINAL = {"completed", "cancelled", "failed"}
DEFAULT_BUDGET = {"input_tokens": 12000, "output_tokens": 4000,
                  "inline_bytes": 32768, "wall_seconds": 300,
                  "tool_calls": 12}

class GateError(ValueError): pass

def _now(): return datetime.now(timezone.utc).isoformat()
def _id(prefix): return "%s_%s" % (prefix, uuid.uuid4().hex)
def _root(path=None): return os.path.abspath(path or os.getcwd())
def _shared_dir_mode(): return 0o770 if os.environ.get("RAT_SHARED_STORE")=="1" else 0o700
_transaction_local=threading.local()
@contextlib.contextmanager
def _transaction(root):
    """Serialize challenge-wide gate transitions and task-cap checks."""
    depth=getattr(_transaction_local,"depth",0)
    if depth:
        _transaction_local.depth=depth+1
        try: yield
        finally: _transaction_local.depth=depth
        return
    lock_dir=os.path.join(_root(root),".rat","locks")
    if not os.path.isdir(lock_dir): os.makedirs(lock_dir,mode=_shared_dir_mode(),exist_ok=True); os.chmod(lock_dir,_shared_dir_mode())
    with open(os.path.join(lock_dir,"orchestration.lock"),"a+",encoding="utf-8") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX); _transaction_local.depth=1
        try: yield
        finally:
            _transaction_local.depth=0; fcntl.flock(lock,fcntl.LOCK_UN)
def _serialized(fn):
    @functools.wraps(fn)
    def wrapped(root,*args,**kwargs):
        with _transaction(root): return fn(root,*args,**kwargs)
    return wrapped
def _task_dir(root):
    p=os.path.join(root,".rat","tasks")
    if not os.path.isdir(p): os.makedirs(p, mode=_shared_dir_mode(), exist_ok=True); os.chmod(p,_shared_dir_mode())
    return p
def _write(path, doc):
    tmp=path+".tmp"
    with open(tmp,"w",encoding="utf-8") as f: json.dump(doc,f,sort_keys=True); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,path)
    if os.environ.get("RAT_SHARED_STORE")=="1": os.chmod(path,0o640)
def _read(path):
    with open(path,encoding="utf-8") as f: return json.load(f)
def _run_id(root):
    try: return _read(os.path.join(root,"run.json"))["run_id"]
    except (OSError, ValueError, KeyError): return "local"
def _phase_state(root):
    active=None; last=None
    for event in Stream(root).read():
        if event["type"] in ("phase.entered", "phase.rollback", "phase.rolled_back"):
            active=event["payload"]["phase"]; last=active
        elif event["type"]=="phase.exited" and active==event["payload"]["phase"]:
            last=active; active=None
    return active,last
def _state(root): return _phase_state(root)[0]
def _active_attempt(root, phase=None):
    active=None; attempt=None
    for event in Stream(root).read():
        if event["type"] in ("phase.entered", "phase.rollback", "phase.rolled_back"):
            active=event["payload"]["phase"]; attempt=event["payload"].get("attempt_id")
        elif event["type"]=="phase.exited" and active==event["payload"]["phase"]:
            active=None; attempt=None
    return attempt if phase is None or active==phase else None
def _last_attempt(root, phase):
    """Return the latest epoch entered for a phase, even after it exited."""
    latest=None
    for event in Stream(root).read():
        if event["type"] in ("phase.entered", "phase.rollback", "phase.rolled_back") and event["payload"].get("phase")==phase:
            latest=event["payload"].get("attempt_id")
    return latest
def _lineage(root):
    """The active evidence epoch; rollback always starts a new lineage."""
    lineage=None
    for event in Stream(root).read():
        if event["type"] in ("phase.entered", "phase.rollback", "phase.rolled_back"):
            lineage=event["payload"].get("lineage_id",lineage)
    return lineage
def _tasks(root):
    d=_task_dir(root); out=[]
    for name in os.listdir(d):
        if name.endswith(".json"):
            try: out.append(_read(os.path.join(d,name)))
            except (OSError,ValueError): pass
    return out
def _task(root, task_id):
    path=os.path.join(_task_dir(root),task_id+".json")
    try: return _read(path),path
    except (OSError, ValueError) as exc: raise GateError("task not found") from exc

def _checkpoint_for_task(root, task):
    """Return the task's immutable input checkpoint, bound to its epoch."""
    path=os.path.join(root,".rat","checkpoints",task["checkpoint_id"]+".json")
    try: cp=_read(path)
    except (OSError, ValueError) as exc: raise GateError("task checkpoint is missing or corrupt") from exc
    if (cp.get("phase"),cp.get("lineage_id")) != (task.get("phase"),task.get("lineage_id")):
        raise GateError("task checkpoint is outside the task phase or lineage")
    # Phase-enter checkpoints precede the task-start checkpoint, so their
    # cursor is the fixed input boundary.  A checkpoint from another attempt
    # must never be replayed after a rollback/re-entry.
    events=Stream(root).read(); by_cursor={e["seq"]:e for e in events}
    event=by_cursor.get(cp.get("event_cursor",{}).get("seq"))
    if not event or event.get("payload",{}).get("attempt_id") not in {None,task.get("phase_attempt_id")}:
        raise GateError("task checkpoint is outside the current phase attempt")
    return cp
def _checkpoint(root, reason, phase, task_id="orchestrator", role="orchestrator"):
    return Stream(root).checkpoint(phase=phase, task_id=task_id, role=role, reason=reason, lineage_id=_lineage(root))
def _pass_primitives(root):
    return [p for p in Stream(root).view()["primitives"].values() if p.get("status")=="pass"]
def _primitive(root, primitive_id, input_digest, environment_digest):
    p=Stream(root).view()["primitives"].get(primitive_id)
    if not p or p.get("status")!="pass": raise GateError("primitive is not an active PASS")
    if p.get("input_digest")!=input_digest or p.get("environment_digest")!=environment_digest:
        raise GateError("primitive environment/input mismatch")
    return p
def _verify_records(root, lineage_id=None):
    stale={e["payload"].get("verification_id") for e in Stream(root).read() if e["type"]=="verification.staled"}
    records=[e["payload"] for e in Stream(root).read() if e["type"]=="verification.recorded" and e["payload"].get("verification_id") not in stale]
    return records if lineage_id is None else [r for r in records if r.get("lineage_id")==lineage_id]
def _require_active_evidence(root, evidence_ids):
    if not isinstance(evidence_ids,list) or not evidence_ids or not all(isinstance(i,str) and i for i in evidence_ids): raise GateError("evidence IDs are required")
    observations=Stream(root).view()["observations"]
    missing=[i for i in evidence_ids if observations.get(i,{}).get("validity",{}).get("state")!="active"]
    if missing: raise GateError("unknown or invalidated evidence: %s" % ", ".join(sorted(set(missing))))
    return evidence_ids
def _skeptic_reports(root, attempt_id=None):
    reports=[e["payload"] for e in Stream(root).read() if e["type"]=="skeptic.reported"]
    return reports if attempt_id is None else [p for p in reports if p.get("phase_attempt_id")==attempt_id]

def validate_contract(contract: dict[str,Any]):
    required={"schema","role","phase","objective","allowed_inputs","required_outputs","forbidden_actions","state_write_scope","capabilities","budgets","stop_conditions"}
    if not isinstance(contract,dict) or set(contract)!=required or contract["schema"]!="rat.role-contract/v1": raise GateError("invalid role contract schema")
    role,phase=contract["role"],contract["phase"]
    if role not in ROLES or phase not in PHASES or phase not in ROLE_PHASES[role]: raise GateError("role is not allowed in this phase")
    if not isinstance(contract["objective"],str) or not contract["objective"].strip(): raise GateError("contract needs an objective")
    if not all(isinstance(contract[k],list) for k in ("allowed_inputs","required_outputs","forbidden_actions","state_write_scope","stop_conditions")): raise GateError("contract list field is invalid")
    budgets=contract["budgets"]
    if not isinstance(budgets,dict) or set(budgets)!=set(DEFAULT_BUDGET) or any(not isinstance(v,int) or v<=0 for v in budgets.values()): raise GateError("contract must define bounded standard budgets")
    caps=contract["capabilities"]
    if not isinstance(caps,dict): raise GateError("invalid capabilities")
    allowed_caps={"network_write","repository_write","evidence_promote","tool_allowlist"}
    if set(caps)-allowed_caps or any(not isinstance(caps.get(k,False),bool) for k in ("network_write","repository_write","evidence_promote")) or ("tool_allowlist" in caps and (not isinstance(caps["tool_allowlist"],list) or not all(isinstance(x,str) and x for x in caps["tool_allowlist"]))): raise GateError("invalid capability declaration")
    if role in {"static-scout","dynamic-scout","hypothesis","skeptic"} and any(caps.get(k) for k in ("network_write","repository_write","evidence_promote")):
        raise GateError("analysis role is read-only")
    if role=="exploit-builder" and caps.get("flag_submit"): raise GateError("flag submission is never a role capability")
    return contract

@_serialized
def enter(root, phase):
    root=_root(root); active,last=_phase_state(root)
    if phase not in PHASES: raise GateError("unknown phase")
    expected=0 if last is None else PHASES.index(last)+1
    if active is not None or expected>=len(PHASES) or PHASES.index(phase)!=expected: raise GateError("previous phase must exit before the next phase enters")
    if phase=="solve-P4" and not _pass_primitives(root): raise GateError("solve-P4 requires an active primitive PASS")
    lineage=_lineage(root) or _id("lineage")
    if phase=="solve-P5":
        p4_attempt=_last_attempt(root,"solve-P4")
        completed=[t for t in _tasks(root) if t["phase"]=="solve-P4" and t.get("lineage_id")==lineage and t.get("phase_attempt_id")==p4_attempt and t["role"]=="exploit-builder" and t["status"]=="completed"]
        if not completed or not any(v.get("verdict")=="pass" and v.get("exploit_task_id") in {t["task_id"] for t in completed} and v.get("exploit_phase_attempt_id")==p4_attempt for v in _verify_records(root,lineage)):
            raise GateError("solve-P5 requires a concrete verification tied to a completed exploit task")
    Stream(root).append("phase.entered",{"phase":phase,"from":last,"run_id":_run_id(root),"attempt_id":_id("attempt"),"lineage_id":lineage})
    return _checkpoint(root,"phase-enter",phase)

@_serialized
def rollback(root, phase, reason, invalidates):
    root=_root(root); current=_state(root)
    if phase not in PHASES or current is None or PHASES.index(phase)>=PHASES.index(current) or not invalidates: raise GateError("rollback needs an earlier phase and invalidated evidence")
    old_lineage=_lineage(root)
    invalidate(root,list(invalidates),reason)
    for task in _tasks(root):
        if task.get("lineage_id")==old_lineage and task.get("status") not in {"cancelled","stale"}:
            if task.get("status")=="running":
                task["cancellation"]=_terminate_task(task)
            task.update({"status":"stale","stale_reason":"rollback:%s" % reason,"staled_at":_now()})
            _write(os.path.join(_task_dir(root),task["task_id"]+".json"),task)
            Stream(root).append("task.staled",task,task_id=task["task_id"])
    for verification in _verify_records(root,old_lineage):
        Stream(root).append("verification.staled",{"verification_id":verification["verification_id"],"reason":"rollback:%s" % reason,"lineage_id":old_lineage})
    Stream(root).append("phase.rollback",{"phase":phase,"from":current,"reason":reason,"invalidates":list(invalidates),"attempt_id":_id("attempt"),"lineage_id":_id("lineage"),"supersedes_lineage_id":old_lineage})
    return _checkpoint(root,"invalidation",phase)

@_serialized
def finish_phase(root, phase, terminal=False):
    root=_root(root)
    if _state(root)!=phase: raise GateError("phase is not active")
    if any(t["phase"]==phase and t["status"] in {"running","repair-needed"} for t in _tasks(root)): raise GateError("active tasks must finish or be cancelled before phase exit")
    if phase=="solve-P5" and terminal:
        attempt=_active_attempt(root,phase); reports=_skeptic_reports(root,attempt)
        skeptics=[t for t in _tasks(root) if t["phase"]==phase and t.get("phase_attempt_id")==attempt and t["role"]=="skeptic" and t["status"]=="completed"]
        if len(reports)!=1 or len(skeptics)!=1 or reports[0].get("task_id")!=skeptics[0]["task_id"] or reports[0].get("verdict")!="accept": raise GateError("verified solve requires one completed skeptic task with accept")
        if not any(v.get("verdict")=="pass" and v.get("exploit_task_id")==reports[0].get("exploit_task_id") for v in _verify_records(root,_lineage(root))): raise GateError("verified solve requires linked concrete verification")
    Stream(root).append("phase.exited",{"phase":phase,"terminal":terminal})
    return _checkpoint(root,"phase-exit",phase)

@_serialized
def start_task(root, contract, *, checkpoint_id, inputs, dependencies=(), primitive_id=None, input_digest=None, environment_digest=None, child_pid=None):
    root=_root(root); validate_contract(contract); phase=_state(root)
    if phase!=contract["phase"]: raise GateError("contract phase is not active")
    if dependencies: _require_active_evidence(root,list(dependencies))
    role=contract["role"]; attempt=_active_attempt(root,phase); lineage=_lineage(root)
    active=[t for t in _tasks(root) if t["status"]=="running"]; same=[t for t in active if t["phase"]==phase and t.get("phase_attempt_id")==attempt]
    if phase in {"solve-P0","solve-P3","solve-P4"} and same: raise GateError("fan-out forbidden in this phase")
    if phase=="solve-P1":
        if len(same)>=3: raise GateError("solve-P1 scout cap is 3")
        locators={tuple(t.get("inputs",[])) for t in same}
        if role in {"static-scout","dynamic-scout"} and tuple(inputs) in locators: raise GateError("duplicate P1 scout input is forbidden")
    if phase=="solve-P2":
        if role!="hypothesis": raise GateError("solve-P2 work must use hypothesis role")
        plans=[e["payload"] for e in Stream(root).read() if e["type"]=="fanout.planned" and e["payload"].get("phase_attempt_id")==attempt]
        if same and not plans: raise GateError("parallel P2 work requires a validated fan-out plan")
        if len(same)>=3: raise GateError("solve-P2 fan-out cap is 3")
        if plans and len(same)>=len(plans[-1]["branches"]): raise GateError("task count exceeds planned branches")
    if phase=="solve-P5":
        if role!="skeptic" or same or any(t["phase"]==phase and t.get("phase_attempt_id")==attempt and t["role"]=="skeptic" for t in _tasks(root)): raise GateError("solve-P5 requires exactly one skeptic")
    if role=="exploit-builder":
        if not all(isinstance(x,str) and x for x in (primitive_id,input_digest,environment_digest)): raise GateError("exploit builder requires primitive and environment provenance")
        _primitive(root,primitive_id,input_digest,environment_digest)
    if role=="skeptic":
        p4_attempt=_last_attempt(root,"solve-P4")
        if not any(v.get("verdict")=="pass" and v.get("exploit_phase_attempt_id")==p4_attempt for v in _verify_records(root,lineage)): raise GateError("skeptic requires prior concrete verification")
    if not checkpoint_id: raise GateError("task requires a fixed input checkpoint")
    cp=os.path.join(root,".rat","checkpoints",checkpoint_id+".json")
    if not os.path.isfile(cp): raise GateError("checkpoint not found")
    if child_pid is not None:
        if not isinstance(child_pid,int) or child_pid<=0: raise GateError("invalid child process-group leader")
        try:
            if os.getpgid(child_pid)!=child_pid: raise GateError("child PID must be its own process-group leader")
        except ProcessLookupError as exc: raise GateError("child process does not exist") from exc
    task={"schema":"rat.task-event/v1","task_id":_id("task"),"run_id":_run_id(root),"phase":phase,"phase_attempt_id":attempt,"lineage_id":lineage,"role":role,"contract":contract,"checkpoint_id":checkpoint_id,"inputs":list(inputs),"dependencies":list(dependencies),"primitive_id":primitive_id,"input_digest":input_digest,"environment_digest":environment_digest,"child_pid":child_pid,"status":"running","started_at":_now(),"budget_used":{}}
    _write(os.path.join(_task_dir(root),task["task_id"]+".json"),task); Stream(root).append("task.started",task,task_id=task["task_id"]); _checkpoint(root,"task-start",phase,task["task_id"],role)
    return task

@_serialized
def reserve_execution(root, task_id, *, wall_seconds):
    """Atomically lease one broker invocation from a live durable task.

    The caller supplies only a task ID; its stored contract is the authority.
    A live lease accounts for concurrent calls before a subprocess starts and
    expires at its reserved deadline if a broker dies before settlement.
    """
    root=_root(root); task,path=_task(root,task_id)
    if task.get("status")!="running": raise GateError("task is not running")
    if task.get("phase")!=_state(root) or task.get("phase_attempt_id")!=_active_attempt(root,task["phase"]) or task.get("lineage_id")!=_lineage(root):
        raise GateError("task is stale for the current phase attempt or lineage")
    _checkpoint_for_task(root,task)
    if not isinstance(wall_seconds,int) or wall_seconds<=0: raise GateError("execution wall budget must be positive")
    limits=task["contract"]["budgets"]; now_mono=time.monotonic()
    leases=[x for x in task.get("execution_leases",[]) if x.get("expires_monotonic",0)>now_mono]
    used=task.get("budget_used",{}); reserved_wall=sum(x["wall_seconds"] for x in leases)
    if used.get("tool_calls",0)+len(leases)+1>limits["tool_calls"] or used.get("wall_seconds",0)+reserved_wall+wall_seconds>limits["wall_seconds"]:
        raise GateError("task execution budget exhausted")
    lease={"lease_id":_id("lease"),"wall_seconds":wall_seconds,"expires_monotonic":now_mono+wall_seconds,"reserved_at":_now()}
    task["execution_leases"]=leases+[lease]; _write(path,task)
    Stream(root).append("task.execution_reserved",{"task_id":task_id,"lease_id":lease["lease_id"],"wall_seconds":wall_seconds,"phase_attempt_id":task["phase_attempt_id"],"lineage_id":task["lineage_id"]},task_id=task_id)
    return {"task":task,"lease":lease}

@_serialized
def settle_execution(root, task_id, lease_id, *, duration_ms):
    root=_root(root); task,path=_task(root,task_id)
    leases=task.get("execution_leases",[]); lease=next((x for x in leases if x.get("lease_id")==lease_id),None)
    if lease is None: raise GateError("unknown or already settled execution lease")
    if not isinstance(duration_ms,int) or duration_ms<0: raise GateError("invalid execution duration")
    used=dict(task.get("budget_used",{})); used["tool_calls"]=used.get("tool_calls",0)+1
    used["wall_seconds"]=used.get("wall_seconds",0)+(duration_ms+999)//1000
    if used["tool_calls"]>task["contract"]["budgets"]["tool_calls"] or used["wall_seconds"]>task["contract"]["budgets"]["wall_seconds"]:
        raise GateError("settled execution exceeded task budget")
    task["execution_leases"]=[x for x in leases if x is not lease]; task["budget_used"]=used; _write(path,task)
    Stream(root).append("task.execution_settled",{"task_id":task_id,"lease_id":lease_id,"duration_ms":duration_ms,"budget_used":used},task_id=task_id)
    return task

@_serialized
def release_execution(root, task_id, lease_id, *, reason):
    """Drop a lease when the broker rejects a request before execution."""
    root=_root(root); task,path=_task(root,task_id)
    leases=task.get("execution_leases",[])
    if not any(x.get("lease_id")==lease_id for x in leases): raise GateError("unknown execution lease")
    task["execution_leases"]=[x for x in leases if x.get("lease_id")!=lease_id]; _write(path,task)
    Stream(root).append("task.execution_released",{"task_id":task_id,"lease_id":lease_id,"reason":reason},task_id=task_id)
    return task

def _valid_output(root, task, output):
    if not isinstance(output,dict) or set(output)!={"schema","task_id","status","outputs","evidence_ids"}: return False
    if output["schema"]!="rat.task-output/v1" or output["task_id"]!=task["task_id"] or output["status"]!="completed": return False
    if not isinstance(output["outputs"],dict): return False
    try: _require_active_evidence(root,output["evidence_ids"])
    except GateError: return False
    return set(task["contract"]["required_outputs"]) <= set(output["outputs"])
def _quarantine(root, task, path, output):
    raw=json.dumps(output,ensure_ascii=False,default=str).encode(); artifact=put_bytes(raw,kind="quarantined-agent-output",media_type="application/json",logical_name=task["task_id"]+".json",root=os.path.join(root,".rat"))
    repairs=task.get("repair_attempts",0)+1; task.update({"repair_attempts":repairs,"quarantined_artifact":artifact["digest"],"status":"repair-needed" if repairs==1 else "cancelled","finished_at":_now()})
    _write(path,task); Stream(root).append("task.output_quarantined",task,task_id=task["task_id"]); _checkpoint(root,"task-end",task["phase"],task["task_id"],task["role"])
    raise GateError("schema-invalid output quarantined; one repair is allowed" if repairs==1 else "schema-invalid output cancelled after repair")
@_serialized
def finish_task(root, task_id, status, output=None, budget_used=None):
    root=_root(root); task,path=_task(root,task_id)
    if task["status"]!="running":
        if task["status"]=="cancelled" and output is not None:
            artifact=put_bytes(json.dumps(output,ensure_ascii=False,default=str).encode(),kind="late-after-invalidation",media_type="application/json",logical_name=task_id+".json",root=os.path.join(root,".rat")); Stream(root).append("task.late_output",{"task_id":task_id,"artifact":artifact["digest"],"reason":task.get("cancel_reason")},task_id=task_id)
        raise GateError("task is not running")
    if status not in TERMINAL: raise GateError("invalid terminal task status")
    used=budget_used or {}; limits=task["contract"]["budgets"]
    if not isinstance(used,dict) or any(k not in limits or not isinstance(v,int) or v<0 for k,v in used.items()): raise GateError("invalid budget usage")
    if status=="completed" and not _valid_output(root,task,output): _quarantine(root,task,path,output)
    if any(used.get(k,0)>limits[k] for k in limits): status="cancelled"; output={"reason":"stop-loss:budget-exhausted"}
    task.update({"status":status,"finished_at":_now(),"output":output,"budget_used":used}); _write(path,task); Stream(root).append("task.finished",task,task_id=task_id); _checkpoint(root,"task-end",task["phase"],task_id,task["role"])
    return task
@_serialized
def repair_task(root, task_id, output, budget_used=None):
    root=_root(root); task,path=_task(root,task_id)
    if task.get("status")!="repair-needed" or task.get("repair_attempts")!=1: raise GateError("task has no permitted repair")
    task["status"]="running"; _write(path,task); return finish_task(root,task_id,"completed",output,budget_used)
@_serialized
def cancel_task(root, task_id, reason):
    root=_root(root); task,path=_task(root,task_id)
    if task["status"]!="running": raise GateError("task is not running")
    if not isinstance(reason,str) or not reason.strip(): raise GateError("cancellation needs a reason")
    task.update({"status":"cancelled","cancel_reason":reason,"cancelled_at":_now(),"cancellation":_terminate_task(task)})
    _write(path,task); Stream(root).append("task.cancelled",task,task_id=task_id); _checkpoint(root,"task-end",task["phase"],task_id,task["role"]); return task

@_serialized
def plan_fanout(root, branches, trigger, budget):
    root=_root(root)
    if _state(root)!="solve-P2": raise GateError("fan-out is only allowed in solve-P2")
    if not isinstance(trigger,dict) or not trigger.get("uncertainty_set"): raise GateError("fan-out trigger needs uncertainty and evidence")
    _require_active_evidence(root,trigger.get("evidence_ids"))
    if not isinstance(branches,list) or not 2<=len(branches)<=3: raise GateError("fan-out requires 2 or 3 branches")
    fingerprints=[]
    for branch in branches:
        if not isinstance(branch,dict) or not {"hypothesis_id","objective","falsification","evidence_ids"}<=set(branch) or branch["objective"]==branch["falsification"]: raise GateError("branch needs evidence and a discriminating probe")
        _require_active_evidence(root,branch.get("evidence_ids"))
        fingerprints.append((branch["objective"],tuple(sorted(branch["evidence_ids"]))))
    if len(set(fingerprints))!=len(fingerprints): raise GateError("duplicate branch input is forbidden")
    if not isinstance(budget,dict) or any(not isinstance(budget.get(k),int) or budget[k]<=0 for k in ("remaining","per_branch","converge")) or budget["remaining"]<budget["per_branch"]*len(branches)+budget["converge"]: raise GateError("insufficient fan-out budget")
    record={"fanout_id":_id("fanout"),"phase":"solve-P2","phase_attempt_id":_active_attempt(root,"solve-P2"),"lineage_id":_lineage(root),"trigger":trigger,"branches":branches,"budget":budget}; Stream(root).append("fanout.planned",record); _checkpoint(root,"fan-out","solve-P2"); return record
@_serialized
def converge(root, retained, refuted, unknowns, rationale):
    root=_root(root)
    if _state(root)!="solve-P2": raise GateError("converge is only allowed in solve-P2")
    if any(t["phase"]=="solve-P2" and t["status"] in {"running","repair-needed"} for t in _tasks(root)): raise GateError("fan-out must reach terminal tasks before converge")
    attempt=_active_attempt(root,"solve-P2"); plans=[e["payload"] for e in Stream(root).read() if e["type"]=="fanout.planned" and e["payload"].get("phase_attempt_id")==attempt]
    valid={b["hypothesis_id"] for b in plans[-1]["branches"]} if plans else set()
    retained,refuted,unknowns=map(set,(retained,refuted,unknowns))
    if not (retained|refuted|unknowns)<=valid or retained&unknowns or not (retained|refuted) or not isinstance(rationale,list) or not rationale: raise GateError("converge must classify planned branches with rationale")
    report={"schema":"rat.converge-report/v1","converge_id":_id("converge"),"run_id":_run_id(root),"phase_attempt_id":attempt,"lineage_id":_lineage(root),"retained":sorted(retained),"refuted":sorted(refuted),"unknowns":sorted(unknowns),"rationale":rationale}; Stream(root).append("fanout.converged",report); _checkpoint(root,"converge","solve-P2"); return report

def _terminate_task(task):
    pid=task.get("child_pid")
    if not pid: return {"requested_at":_now(),"acknowledged_at":None,"forced_at":None}
    requested=_now(); acknowledged=forced=None
    try: os.killpg(pid,signal.SIGTERM)
    except ProcessLookupError: acknowledged=_now()
    else:
        deadline=time.monotonic()+1.0
        while time.monotonic()<deadline:
            try: os.kill(pid,0)
            except ProcessLookupError: acknowledged=_now(); break
            time.sleep(.02)
        if acknowledged is None:
            try: os.killpg(pid,signal.SIGKILL); forced=_now()
            except ProcessLookupError: acknowledged=_now()
    return {"requested_at":requested,"acknowledged_at":acknowledged,"forced_at":forced}
@_serialized
def invalidate(root, observation_ids, reason):
    root=_root(root)
    if not observation_ids or not reason: raise GateError("invalidation needs evidence and reason")
    s=Stream(root); event=s.append("evidence.invalidated",{"observation_ids":list(observation_ids),"reason":reason}); affected=[]
    for task in _tasks(root):
        if task["status"]=="running" and set(task.get("dependencies",[]))&set(observation_ids):
            task.update({"status":"cancelled","cancel_reason":"invalidation:"+event["event_id"],"cancelled_at":_now(),"cancellation":_terminate_task(task)}); _write(os.path.join(_task_dir(root),task["task_id"]+".json"),task); s.append("task.cancelled",task,task_id=task["task_id"]); affected.append(task["task_id"])
    phase=_state(root) or "solve-P0"; _checkpoint(root,"invalidation",phase); return {"event_id":event["event_id"],"cancelled":affected}

@_serialized
def report_skeptic(root, report):
    root=_root(root); required={"schema","report_id","run_id","task_id","exploit_task_id","verdict","counterexamples","affected_ids","residual_risks"}
    if not isinstance(report,dict) or set(report)!=required or report["schema"]!="rat.skeptic-report/v1" or report["verdict"] not in {"accept","refute","inconclusive"}: raise GateError("invalid skeptic report")
    attempt=_active_attempt(root,"solve-P5")
    if _state(root)!="solve-P5" or not attempt or _skeptic_reports(root,attempt) or report["run_id"]!=_run_id(root): raise GateError("skeptic report is not permitted")
    task,_=_task(root,report["task_id"])
    if task["phase"]!="solve-P5" or task.get("phase_attempt_id")!=attempt or task["role"]!="skeptic" or task["status"]!="completed": raise GateError("skeptic report requires completed skeptic task")
    exploit,_=_task(root,report["exploit_task_id"])
    if exploit["phase"]!="solve-P4" or exploit["role"]!="exploit-builder" or exploit["status"]!="completed" or exploit.get("lineage_id")!=_lineage(root): raise GateError("skeptic report requires completed exploit task in current lineage")
    Stream(root).append("skeptic.reported",report|{"phase_attempt_id":attempt,"lineage_id":_lineage(root)},actor="skeptic",task_id=task["task_id"]); _checkpoint(root,"task-end","solve-P5",task["task_id"],"skeptic"); return report
def _verification_report(root, report_digest):
    """Load the sole authority for a verification promotion.

    Verification reports are content-addressed artifacts emitted by rat-verify.
    The orchestration layer intentionally never accepts a caller-supplied
    verdict: doing so would recreate the exact promotion bypass rat-verify is
    meant to prevent.
    """
    if not isinstance(report_digest,str) or not report_digest.startswith("sha256:"):
        raise GateError("verification requires an immutable report artifact digest")
    try:
        report=json.loads(get(report_digest,root=os.path.join(root,".rat")))
    except Exception as exc:
        raise GateError("verification report artifact is missing or invalid") from exc
    provenance=report.get("provenance")
    required={"schema","verdict","repetitions","environment_match","scope","provenance","results","producer"}
    if set(report)!=required or report["schema"]!="rat.verification-report/v1":
        raise GateError("verification report schema is invalid")
    if report["verdict"] not in {"pass","fail","inconclusive"} or not isinstance(report["repetitions"],int) or report["repetitions"]<1:
        raise GateError("verification report verdict or repetitions are invalid")
    if not isinstance(report["environment_match"],bool) or not isinstance(report["results"],list) or len(report["results"])!=report["repetitions"]:
        raise GateError("verification report result set is invalid")
    if not isinstance(provenance,dict) or set(provenance)!={"claim_id","primitive_id","exploit_task_id","trace_digest","environment_digest"}:
        raise GateError("verification report provenance is invalid")
    producer=report["producer"]
    if not isinstance(producer,dict) or set(producer)!={"tool","build_digest"} or producer["tool"]!="rat-verify" or not isinstance(producer["build_digest"],str) or not producer["build_digest"].startswith("sha256:"):
        raise GateError("verification report producer provenance is invalid")
    if not all(isinstance(provenance[k],str) and provenance[k] for k in provenance) or not provenance["trace_digest"].startswith("sha256:") or not provenance["environment_digest"].startswith("sha256:"):
        raise GateError("verification report digest provenance is invalid")
    return report

def _broker_receipt(root, receipt_digest, report_digest, report, exploit_task):
    """Authenticate a verification report against its broker execution.

    The report is untrusted content.  Promotion is permitted only when an
    immutable broker receipt for the current exploit task records the exact
    report object as a produced artifact and the executing verifier identity.
    """
    if not isinstance(receipt_digest,str) or not receipt_digest.startswith("sha256:"):
        raise GateError("verification requires a broker receipt artifact")
    try: receipt=json.loads(get(receipt_digest,root=os.path.join(root,".rat")))
    except Exception as exc: raise GateError("broker receipt artifact is missing or invalid") from exc
    required={"schema","receipt_id","task_id","checkpoint_id","phase_attempt_id","lineage_id","lease_id","tool","inputs","sandbox","result","signature"}
    if not isinstance(receipt,dict) or set(receipt)!=required or receipt["schema"]!="rat.broker-receipt/v1":
        raise GateError("broker receipt schema is invalid")
    if not verify_receipt(os.path.join(root,".rat"),receipt): raise GateError("broker receipt signature is invalid")
    if receipt["task_id"]!=exploit_task["task_id"] or receipt["checkpoint_id"]!=exploit_task["checkpoint_id"] or receipt["phase_attempt_id"]!=exploit_task["phase_attempt_id"] or receipt["lineage_id"]!=exploit_task["lineage_id"]:
        raise GateError("broker receipt is not bound to this exploit task")
    tool=receipt.get("tool",{}); producer=report["producer"]
    if tool.get("name")!="rat-verify" or tool.get("build_digest")!=producer["build_digest"]:
        raise GateError("broker receipt verifier identity does not match report")
    result=receipt.get("result",{}); artifacts=result.get("artifacts",[])
    if not isinstance(artifacts,list) or report_digest not in {x.get("digest") for x in artifacts if isinstance(x,dict)}:
        raise GateError("broker receipt does not link the verification report output")
    if receipt["lease_id"] in {e["payload"].get("receipt_lease_id") for e in Stream(root).read() if e["type"]=="verification.recorded"}:
        raise GateError("broker receipt lease was already consumed")
    return receipt

@_serialized
def record_verification(root, report_digest, evidence_ids, receipt_digest):
    """Record a verifier-produced result and promote only an authenticated PASS."""
    root=_root(root); report=_verification_report(root,report_digest); provenance=report["provenance"]
    verdict=report["verdict"]; task=None
    if verdict=="pass":
        if not report["environment_match"]: raise GateError("verification PASS requires a matching environment")
        _require_active_evidence(root,list(evidence_ids))
        task,_=_task(root,provenance["exploit_task_id"])
        if task["phase"]!="solve-P4" or task["role"]!="exploit-builder" or task["status"]!="completed" or task.get("primitive_id")!=provenance["primitive_id"]:
            raise GateError("verification must be linked to completed exploit and its primitive")
        if task.get("environment_digest")!=provenance["environment_digest"]:
            raise GateError("verification report environment does not match exploit task")
        _primitive(root,provenance["primitive_id"],task.get("input_digest"),task.get("environment_digest"))
    # Fail closed for non-PASS reports too: otherwise a forged inconclusive
    # report could be used to manipulate phase history or consume a receipt.
    if task is None:
        task,_=_task(root,provenance["exploit_task_id"])
    receipt=_broker_receipt(root,receipt_digest,report_digest,report,task)
    record={"verification_id":_id("verify"),"report_digest":report_digest,"receipt_digest":receipt_digest,"receipt_lease_id":receipt["lease_id"],"verdict":verdict,"evidence_ids":list(evidence_ids),"environment_match":report["environment_match"],"exploit_task_id":provenance["exploit_task_id"],"primitive_id":provenance["primitive_id"],"trace_digest":provenance["trace_digest"],"producer_build_digest":report["producer"]["build_digest"],"exploit_phase_attempt_id":task.get("phase_attempt_id"),"lineage_id":task.get("lineage_id")}
    Stream(root).append("verification.recorded",record)
    return record

def record_verification_from_receipt(root, receipt_digest, evidence_ids):
    """Promote the single broker-linked verifier report without caller pairing."""
    root=_root(root)
    try: receipt=json.loads(get(receipt_digest,root=os.path.join(root,".rat")))
    except Exception as exc: raise GateError("broker receipt artifact is missing or invalid") from exc
    report_digest=receipt.get("result",{}).get("verification_report_digest")
    if not isinstance(report_digest,str) or not report_digest.startswith("sha256:"):
        raise GateError("broker receipt has no imported verification report")
    return record_verification(root,report_digest,evidence_ids,receipt_digest)
def context_bundle(root, checkpoint_id, phase, budget):
    root=_root(root)
    if phase not in PHASES or not isinstance(budget,int) or budget<=0 or budget>DEFAULT_BUDGET["inline_bytes"]: raise GateError("invalid context request")
    path=os.path.join(root,".rat","checkpoints",checkpoint_id+".json")
    if not os.path.isfile(path): raise GateError("checkpoint not found")
    cp=_read(path); delta=Stream(root).delta(cp["event_cursor"]); payload={"checkpoint_id":checkpoint_id,"phase":phase,"cursor":cp["event_cursor"],"delta":[{"seq":e["seq"],"type":e["type"],"event_id":e["event_id"]} for e in delta]}; raw=json.dumps(payload,separators=(",",":"),ensure_ascii=False).encode()
    if len(raw)>budget:
        artifact=put_bytes(raw,kind="context-delta",media_type="application/json",logical_name="delta.json",root=os.path.join(root,".rat")); payload={"checkpoint_id":checkpoint_id,"phase":phase,"cursor":cp["event_cursor"],"delta_artifact":artifact["digest"],"truncated":True}
    return payload
