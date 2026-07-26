"""Fail-closed role-contract authorization boundary.

Agents pass a role contract and artifact IDs to this broker instead of treating
the free-text contract as permission.  It deliberately authorizes only; a
transport may use the decision to start a bounded process, but cannot turn a
denied capability into a shell escape.
"""
from __future__ import annotations
import hashlib, json
import os
import shutil
import socket
import stat
import re
from typing import Iterable

from .artifact import get, metadata, put_bytes
from .orchestration import GateError, release_execution, reserve_execution, settle_execution, validate_contract
from .receipt import sign as sign_receipt
from .runner import run
from .runtime import active_path

_ACTIONS={"network-write":"network_write", "repository-write":"repository_write",
          "evidence-promote":"evidence_promote", "tool-run":None,
          "state-write":None}
_TARGET=re.compile(r"(?:(?P<user>[^@:\s]+)@)?(?P<host>[^:\s]+):(?P<port>[1-9][0-9]{0,4})\Z")

def authorize(contract: dict, action: str, *, inputs: Iterable[str]=(),
              state_event: str | None=None, tool: str | None=None,
              artifact_root: str | None=None) -> dict:
    validate_contract(contract)
    if action not in _ACTIONS: raise GateError("unknown broker action")
    if action in contract["forbidden_actions"]: raise GateError("action forbidden by role contract")
    capability=_ACTIONS[action]
    if capability and not contract["capabilities"].get(capability,False):
        raise GateError("role lacks %s capability" % capability)
    if action=="state-write":
        if not state_event or state_event not in contract["state_write_scope"]:
            raise GateError("state event is outside the role write scope")
    if action=="tool-run":
        if not tool or os.path.basename(tool) not in contract["capabilities"].get("tool_allowlist",[]):
            raise GateError("tool is not allowlisted for this role")
    permitted=contract["allowed_inputs"]
    checked=[]
    for digest in inputs:
        if not isinstance(digest,str) or not digest.startswith("sha256:"): raise GateError("broker inputs must be artifact digests")
        if digest not in permitted: raise GateError("artifact input is outside the role allowlist")
        try: get(digest,root=artifact_root)
        except Exception as exc: raise GateError("artifact input is missing or corrupt") from exc
        checked.append(digest)
    return {"authorized":True,"role":contract["role"],"phase":contract["phase"],"action":action,"inputs":checked,"state_event":state_event,"tool":os.path.basename(tool) if tool else None}

def _materialize(root: str, digest: str, *, destination_root: str | None=None, sandbox_prefix: str | None=None, executable: bool=False) -> str:
    """Expose an approved object at a deterministic, non-user-chosen path."""
    data=get(digest,root=root)
    destination_root=destination_root or root
    directory=os.path.join(destination_root,"materialized")
    os.makedirs(directory,mode=0o700,exist_ok=True)
    path=os.path.join(directory,digest.removeprefix("sha256:"))
    if not os.path.exists(path):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o500 if executable else 0o400)
        try:
            os.write(fd,data); os.fsync(fd)
        finally: os.close(fd)
    mode=stat.S_IMODE(os.stat(path).st_mode)
    expected=0o500 if executable else 0o400
    if mode!=expected: os.chmod(path,expected)
    return os.path.join(sandbox_prefix,os.path.basename(path)) if sandbox_prefix else path

def _stage_inputs(source_root: str, output_root: str, digests: Iterable[str]):
    """Copy approved immutable inputs into the sandbox's isolated object store."""
    for digest in digests:
        record=metadata(digest,root=source_root)
        put_bytes(get(digest,root=source_root),kind=record["kind"],media_type=record["media_type"],logical_name=record["logical_name"],root=output_root,provenance=record.get("provenance",{}))

def _import_output(output_root: str, destination_root: str):
    """Validate and import only content-addressed sandbox output objects."""
    base=os.path.join(output_root,"metadata","sha256"); imported=[]
    if not os.path.isdir(base): return imported
    for prefix in sorted(os.listdir(base)):
        directory=os.path.join(base,prefix)
        if len(prefix)!=2 or not os.path.isdir(directory): raise GateError("sandbox output metadata layout is invalid")
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".json"): raise GateError("sandbox output metadata filename is invalid")
            try:
                with open(os.path.join(directory,name),encoding="utf-8") as source: record=json.load(source)
                digest=record["digest"]
                if record.get("schema")!="rat.artifact/v1" or name[:-5]!=digest[9:] or prefix!=digest[7:9]: raise ValueError("artifact metadata does not match digest")
                stored=put_bytes(get(digest,root=output_root),kind=record["kind"],media_type=record["media_type"],logical_name=record["logical_name"],root=destination_root,provenance={"broker_import":True,"sandbox_provenance":record.get("provenance",{})})
            except (OSError,ValueError,KeyError,TypeError) as exc: raise GateError("sandbox output artifact is invalid") from exc
            imported.append({k:stored[k] for k in ("digest","kind","media_type","size","logical_name")})
    return imported

def _tool_result_from_stdout(data: bytes):
    try: doc=json.loads(data.decode())
    except (UnicodeDecodeError,json.JSONDecodeError): return None
    return doc if isinstance(doc,dict) and doc.get("schema")=="rat.tool-result/v1" else None

def _bound_argv(argv: list[str], bindings: dict[int,str], permitted: set[str], root: str, *, destination_root: str | None=None, sandbox_prefix: str | None=None) -> list[str]:
    """Replace every file-like tool argument with its registered artifact.

    A pinned top-level tool is not enough: ``rat-verify --oracle /tmp/x`` is
    an escape unless every subordinate binary/scenario/oracle path is bound to
    a digest.  Reject unbound path-looking arguments rather than attempting to
    infer a safe path policy from a tool's free-form argv.
    """
    if not isinstance(bindings,dict) or any(not isinstance(i,int) or i<1 or not isinstance(d,str) for i,d in bindings.items()):
        raise GateError("broker artifact bindings must map argv indexes to digests")
    out=list(argv)
    for index,digest in bindings.items():
        if index>=len(out) or digest not in permitted: raise GateError("argv binding is outside approved artifacts")
        # Tool-specific argv schemas, not caller metadata, decide whether a
        # staged object is executable.  Verification/dynamic execution accept
        # a challenge-binary only at their positional binary argument; an
        # oracle is executable only behind its explicit option.
        tool=os.path.basename(out[0]); kind=metadata(digest,root=root).get("kind")
        executable=out[index-1]=="--oracle" or (tool in {"rat-verify","rat-dyn"} and index==1 and kind=="challenge-binary")
        out[index]=_materialize(root,digest,destination_root=destination_root,sandbox_prefix=sandbox_prefix,executable=executable)
    for index,arg in enumerate(out[1:],1):
        if index in bindings: continue
        if os.path.isabs(arg) or arg.startswith(".") or os.sep in arg:
            raise GateError("file-like argv values must be bound to an approved artifact digest")
    return out

def _network_policy(challenge_dir: str, ctf_home: str):
    """Read one ctfguard-registered target from the solve-owned manifest."""
    try:
        with open(os.path.join(challenge_dir,"run.json"),encoding="utf-8") as source: policy=json.load(source)["target_policy"]
        with open(active_path(ctf_home),encoding="utf-8") as source: active=json.load(source)
    except (OSError,ValueError,KeyError) as exc: raise GateError("network task requires an active ctfguard target policy") from exc
    allowlist=policy.get("allowlist",[])
    if policy.get("network_mode")!="ctfguard-target" or not isinstance(allowlist,list) or len(allowlist)!=1 or policy.get("guard_challenge")!=active.get("chal"):
        raise GateError("network task requires exactly one active ctfguard target")
    match=_TARGET.fullmatch(allowlist[0]) if isinstance(allowlist[0],str) else None
    if not match or not 1<=int(match["port"])<=65535: raise GateError("network target format is invalid")
    hostport="%s:%s" % (match["host"],match["port"])
    if allowlist[0] not in active.get("targets",[]) and hostport not in active.get("targets",[]):
        raise GateError("network target is not in active ctfguard allowlist")
    return {"host":match["host"],"port":int(match["port"]),"target":allowlist[0]}

def _pinned_hosts(output_dir: str, policy: dict) -> str:
    """Create a resolver-free hostname mapping inside one sandbox invocation."""
    try:
        addresses=sorted({item[4][0] for item in socket.getaddrinfo(policy["host"],None,family=socket.AF_INET,type=socket.SOCK_STREAM)})
    except OSError as exc:
        raise GateError("network target hostname did not resolve") from exc
    if not addresses: raise GateError("network target hostname has no IPv4 address")
    path=os.path.join(output_dir,"pinned-hosts")
    with open(path,"w",encoding="ascii") as out:
        out.write("127.0.0.1 localhost\n")
        for address in addresses: out.write("%s %s\n" % (address,policy["host"]))
    os.chmod(path,0o444)
    return path

def _sandbox_argv(argv: list[str], *, root: str, ctf_home: str, challenge_dir: str, network_write: bool, output_dir: str, network_policy=None) -> list[str]:
    """Return a fail-closed bubblewrap command with a read-only repository.

    The artifact store is the only writable mount.  A missing or unusable
    bubblewrap installation is a policy failure, not a reason to inherit host
    network/filesystem authority.
    """
    bwrap=shutil.which("bwrap")
    if not bwrap: raise GateError("broker requires bubblewrap for OS policy enforcement")
    if not os.path.isdir(challenge_dir): raise GateError("broker challenge directory is missing")
    # Do not bind the host root.  The repository is read-only, but the real
    # artifact/task store is masked after that bind; the child sees only the
    # broker-staged object store at /rat-output plus its writable output area.
    command=[bwrap,"--die-with-parent","--new-session","--ro-bind","/usr","/usr","--ro-bind","/bin","/bin","--ro-bind","/lib","/lib","--dev","/dev","--proc","/proc","--tmpfs","/tmp","--ro-bind",ctf_home,ctf_home,"--tmpfs",root,"--bind",output_dir,"/rat-output","--chdir",challenge_dir]
    if os.path.exists("/lib64"): command[1:1]=["--ro-bind","/lib64","/lib64"]
    # bwrap alone has no target-filtered egress primitive.  Until a dedicated
    # proxy/netns policy is installed, even network-capable contracts fail
    # closed rather than silently inheriting the host network.
    if not network_write: return command+["--unshare-net","--",*argv]
    runner=os.environ.get("RAT_BROKER_NETWORK_RUNNER")
    if not runner or not os.path.isabs(runner) or not os.path.isfile(runner) or not os.access(runner,os.X_OK) or not network_policy:
        raise GateError("target-filtered network runner is required; host network is never inherited")
    # Bubblewrap gets no resolver configuration. Pin the active target in a
    # private hosts file so a hostname cannot trigger a DNS egress escape.
    hosts=_pinned_hosts(output_dir,network_policy)
    command.extend(["--dir","/etc","--ro-bind",hosts,"/etc/hosts"])
    # The adapter is broker-owned deployment configuration, not an agent argv.
    # Its contract is to create a network namespace permitting only this TCP
    # destination, then execute the supplied bubblewrap command.
    return [runner,"--allow-host",network_policy["host"],"--allow-port",str(network_policy["port"]),"--",*command,"--",*argv]

def run_authorized(contract: dict, argv: list[str], *, inputs: Iterable[str]=(),
                   bindings: dict[int,str] | None=None, artifact_root: str | None=None,
                   ctf_home: str | None=None, challenge_dir: str | None=None) -> dict:
    """Execute a contract-approved CTF-Rat tool with the role wall budget.

    The executable identity is pinned to ``CTF_HOME/bin``: an allowlisted
    basename alone is not sufficient to substitute an arbitrary lookalike.
    """
    if not isinstance(argv,list) or not argv or not all(isinstance(arg,str) and arg for arg in argv): raise GateError("broker command must be argv-only")
    root=os.path.abspath(artifact_root or os.path.join(os.getcwd(),".rat"))
    tool=os.path.basename(argv[0]); decision=authorize(contract,"tool-run",inputs=inputs,tool=tool,artifact_root=root)
    home=os.path.abspath(ctf_home or os.environ.get("CTF_HOME") or os.path.join(os.path.dirname(__file__),"..",".."))
    trusted=os.path.realpath(os.path.join(home,"bin",tool))
    if os.path.realpath(argv[0])!=trusted or not os.path.isfile(trusted): raise GateError("broker only executes the pinned CTF-Rat tool path")
    challenge=os.path.abspath(challenge_dir or os.getcwd())
    if os.path.commonpath([home,challenge])!=home: raise GateError("broker challenge directory must be inside CTF_HOME")
    execution_root=os.path.join(root,"execution"); os.makedirs(execution_root,mode=0o700,exist_ok=True)
    output_dir=__import__("tempfile").mkdtemp(prefix="broker-",dir=execution_root)
    _stage_inputs(root,output_dir,decision["inputs"])
    bound=_bound_argv([trusted,*argv[1:]],bindings or {},set(decision["inputs"]),root,destination_root=output_dir,sandbox_prefix="/rat-output/materialized")
    policy=_network_policy(challenge,home) if contract["capabilities"]["network_write"] else None
    command=_sandbox_argv(bound,root=root,ctf_home=home,challenge_dir=challenge,network_write=contract["capabilities"]["network_write"],output_dir=output_dir,network_policy=policy)
    result=run(command,cwd=challenge,env={"RAT_ARTIFACT_ROOT":"/rat-output"},timeout_seconds=contract["budgets"]["wall_seconds"],spool_dir=output_dir,tool_version="rat-broker/v1")
    artifacts=[]
    for label,captured in (("stdout",result.stdout),("stderr",result.stderr)):
        data=open(captured.spool_path,"rb").read() if captured.spool_path else captured.preview
        record=put_bytes(data,kind="broker-"+label,media_type="application/octet-stream",logical_name=label+".bin",root=root)
        artifacts.append({k:record[k] for k in ("digest","kind","media_type","size","logical_name")})
    imported=_import_output(output_dir,root); artifacts.extend(imported)
    if result.exit_code and b"bwrap:" in result.stderr.preview:
        raise GateError("broker sandbox could not enforce execution policy")
    stdout_data=open(result.stdout.spool_path,"rb").read() if result.stdout.spool_path else result.stdout.preview
    envelope=_tool_result_from_stdout(stdout_data); verification_report=None
    if tool=="rat-verify" and envelope:
        reports=[x.get("digest") for x in envelope.get("artifacts",[]) if isinstance(x,dict) and x.get("kind")=="verification-report"]
        if len(reports)==1 and reports[0] in {x["digest"] for x in imported}: verification_report=reports[0]
    response={"authorized":True,"tool":tool,"exit_code":result.exit_code,"timed_out":result.timed_out,"duration_ms":result.duration_ms,"artifacts":artifacts,"verification_report_digest":verification_report,"sandbox":{"network":policy or "none","filesystem":"repository-read-only"}}
    shutil.rmtree(output_dir)
    try: os.rmdir(execution_root)
    except OSError: pass  # another invocation may own a sibling output dir
    return response

def run_task(task_root: str, task_id: str, argv: list[str], *, inputs: Iterable[str]=(), bindings: dict[int,str] | None=None, ctf_home: str | None=None, wall_seconds: int | None=None) -> dict:
    """Run only under a current durable task and emit a broker receipt."""
    root=os.path.abspath(task_root); artifact_root=os.path.join(root,".rat")
    # Reserve before reading/executing anything; this closes concurrent budget
    # races and makes a task ID, not caller JSON, the sole authority.
    task_path=os.path.join(artifact_root,"tasks",task_id+".json")
    try:
        with open(task_path,encoding="utf-8") as source: stored=json.load(source)
    except (OSError,ValueError) as exc: raise GateError("task not found") from exc
    requested=wall_seconds if wall_seconds is not None else stored["contract"]["budgets"]["wall_seconds"]
    reservation=reserve_execution(root,task_id,wall_seconds=requested)
    try:
        result=run_authorized(reservation["task"]["contract"],argv,inputs=inputs,bindings=bindings,artifact_root=artifact_root,ctf_home=ctf_home,challenge_dir=root)
    except Exception as exc:
        release_execution(root,task_id,reservation["lease"]["lease_id"],reason="launch-denied:%s" % type(exc).__name__)
        raise
    settle_execution(root,task_id,reservation["lease"]["lease_id"],duration_ms=result["duration_ms"])
    receipt={"schema":"rat.broker-receipt/v1","receipt_id":"receipt_"+hashlib.sha256((task_id+reservation["lease"]["lease_id"]).encode()).hexdigest()[:24],"task_id":task_id,"checkpoint_id":reservation["task"]["checkpoint_id"],"phase_attempt_id":reservation["task"]["phase_attempt_id"],"lineage_id":reservation["task"]["lineage_id"],"lease_id":reservation["lease"]["lease_id"],"tool":{"name":result["tool"],"build_digest":"sha256:"+hashlib.sha256(open(argv[0],"rb").read()).hexdigest()},"inputs":list(inputs),"sandbox":result["sandbox"],"result":{"exit_code":result["exit_code"],"timed_out":result["timed_out"],"duration_ms":result["duration_ms"],"artifacts":result["artifacts"],"verification_report_digest":result["verification_report_digest"]}}
    receipt["signature"]=sign_receipt(artifact_root,receipt)
    record=put_bytes(json.dumps(receipt,sort_keys=True,separators=(",",":")).encode(),kind="broker-receipt",media_type="application/json",logical_name=receipt["receipt_id"]+".json",root=artifact_root,provenance={"broker":True,"task_id":task_id})
    return result|{"task_id":task_id,"receipt_digest":record["digest"]}

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(prog="rat-broker")
    parser.add_argument("--task",required=True)
    parser.add_argument("--root",default=os.getcwd(),help="challenge root containing .rat")
    parser.add_argument("--wall-seconds",type=int)
    parser.add_argument("--socket",help="broker-owned Unix socket; required for privileged deployment")
    parser.add_argument("--action",required=True,choices=sorted(_ACTIONS))
    parser.add_argument("--input",action="append",default=[])
    parser.add_argument("--state-event")
    parser.add_argument("--tool")
    parser.add_argument("--bind",action="append",default=[],metavar="INDEX=DIGEST")
    parser.add_argument("--run",nargs=__import__("argparse").REMAINDER,default=[])
    args=parser.parse_args(argv)
    try:
        bindings={}
        for raw in args.bind:
            index,digest=raw.split("=",1); index=int(index)
            if index in bindings: raise GateError("duplicate argv binding")
            bindings[index]=digest
        if args.run:
            if args.action!="tool-run": raise GateError("--run requires tool-run action")
            if os.environ.get("RAT_BROKER_REQUIRE_SOCKET")=="1" and not args.socket:
                raise GateError("production broker mode requires --socket")
            payload={"action":"tool-run","task_id":args.task,"root":args.root,"argv":args.run,"inputs":args.input,"bindings":bindings,"wall_seconds":args.wall_seconds}
            if args.socket:
                from .broker_service import request as broker_request
                result=broker_request(args.socket,payload)
            else:
                result=run_task(args.root,args.task,args.run,inputs=args.input,bindings=bindings,wall_seconds=args.wall_seconds)
            print(json.dumps(result,sort_keys=True))
        else:
            raise GateError("broker authorization decisions are available only through --run under a durable task")
        return 0
    except (OSError,ValueError,GateError,json.JSONDecodeError) as exc:
        print("[rat-broker:policy] %s" % exc, file=__import__("sys").stderr)
        return 5
