"""Fail-closed role-contract authorization boundary.

Agents pass a role contract and artifact IDs to this broker instead of treating
the free-text contract as permission.  It deliberately authorizes only; a
transport may use the decision to start a bounded process, but cannot turn a
denied capability into a shell escape.
"""
from __future__ import annotations
import json
import os
import shutil
import stat
from typing import Iterable

from .artifact import get, put_bytes
from .orchestration import GateError, validate_contract
from .runner import run

_ACTIONS={"network-write":"network_write", "repository-write":"repository_write",
          "evidence-promote":"evidence_promote", "tool-run":None,
          "state-write":None}

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

def _materialize(root: str, digest: str, *, executable: bool=False) -> str:
    """Expose an approved object at a deterministic, non-user-chosen path."""
    data=get(digest,root=root)
    directory=os.path.join(root,"materialized")
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
    return path

def _bound_argv(argv: list[str], bindings: dict[int,str], permitted: set[str], root: str) -> list[str]:
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
        # Only an explicitly bound oracle is executable.  Other artifacts are
        # data, even if their original host path had execute permissions.
        executable=out[index-1]=="--oracle"
        out[index]=_materialize(root,digest,executable=executable)
    for index,arg in enumerate(out[1:],1):
        if index in bindings: continue
        if os.path.isabs(arg) or arg.startswith(".") or os.sep in arg:
            raise GateError("file-like argv values must be bound to an approved artifact digest")
    return out

def _sandbox_argv(argv: list[str], *, root: str, challenge_dir: str, network_write: bool) -> list[str]:
    """Return a fail-closed bubblewrap command with a read-only repository.

    The artifact store is the only writable mount.  A missing or unusable
    bubblewrap installation is a policy failure, not a reason to inherit host
    network/filesystem authority.
    """
    bwrap=shutil.which("bwrap")
    if not bwrap: raise GateError("broker requires bubblewrap for OS policy enforcement")
    if not os.path.isdir(challenge_dir): raise GateError("broker challenge directory is missing")
    # The underlying host is mounted read-only.  Rebinding .rat read/write
    # permits tool-generated artifacts while keeping source and repository
    # metadata immutable to analysis roles.
    command=[bwrap,"--die-with-parent","--new-session","--ro-bind","/","/","--dev","/dev","--proc","/proc","--tmpfs","/tmp","--bind",root,root,"--chdir",challenge_dir]
    if not network_write: command.append("--unshare-net")
    return command+["--",*argv]

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
    bound=_bound_argv([trusted,*argv[1:]],bindings or {},set(decision["inputs"]),root)
    challenge=os.path.abspath(challenge_dir or os.getcwd())
    if os.path.commonpath([home,challenge])!=home: raise GateError("broker challenge directory must be inside CTF_HOME")
    command=_sandbox_argv(bound,root=root,challenge_dir=challenge,network_write=contract["capabilities"]["network_write"])
    result=run(command,cwd=challenge,timeout_seconds=contract["budgets"]["wall_seconds"],spool_dir=os.path.join(root,"tmp"),tool_version="rat-broker/v1")
    artifacts=[]
    for label,captured in (("stdout",result.stdout),("stderr",result.stderr)):
        data=open(captured.spool_path,"rb").read() if captured.spool_path else captured.preview
        record=put_bytes(data,kind="broker-"+label,media_type="application/octet-stream",logical_name=label+".bin",root=root)
        artifacts.append({k:record[k] for k in ("digest","kind","media_type","size","logical_name")})
    if result.exit_code and b"bwrap:" in result.stderr.preview:
        raise GateError("broker sandbox could not enforce execution policy")
    return {"authorized":True,"tool":tool,"exit_code":result.exit_code,"timed_out":result.timed_out,"duration_ms":result.duration_ms,"artifacts":artifacts,"sandbox":{"network":"inherit" if contract["capabilities"]["network_write"] else "none","filesystem":"repository-read-only"}}

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(prog="rat-broker")
    parser.add_argument("--contract",required=True)
    parser.add_argument("--root",default=os.path.join(os.getcwd(),".rat"))
    parser.add_argument("--action",required=True,choices=sorted(_ACTIONS))
    parser.add_argument("--input",action="append",default=[])
    parser.add_argument("--state-event")
    parser.add_argument("--tool")
    parser.add_argument("--bind",action="append",default=[],metavar="INDEX=DIGEST")
    parser.add_argument("--run",nargs=__import__("argparse").REMAINDER,default=[])
    args=parser.parse_args(argv)
    try:
        with open(args.contract,encoding="utf-8") as source: contract=json.load(source)
        bindings={}
        for raw in args.bind:
            index,digest=raw.split("=",1); index=int(index)
            if index in bindings: raise GateError("duplicate argv binding")
            bindings[index]=digest
        if args.run:
            if args.action!="tool-run": raise GateError("--run requires tool-run action")
            print(json.dumps(run_authorized(contract,args.run,inputs=args.input,bindings=bindings,artifact_root=args.root),sort_keys=True))
        else:
            print(json.dumps(authorize(contract,args.action,inputs=args.input,state_event=args.state_event,tool=args.tool,artifact_root=args.root),sort_keys=True))
        return 0
    except (OSError,ValueError,GateError,json.JSONDecodeError) as exc:
        print("[rat-broker:policy] %s" % exc, file=__import__("sys").stderr)
        return 5
