"""Fail-closed role-contract authorization boundary.

Agents pass a role contract and artifact IDs to this broker instead of treating
the free-text contract as permission.  It deliberately authorizes only; a
transport may use the decision to start a bounded process, but cannot turn a
denied capability into a shell escape.
"""
from __future__ import annotations
import json
import os
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

def run_authorized(contract: dict, argv: list[str], *, inputs: Iterable[str]=(),
                   artifact_root: str | None=None, ctf_home: str | None=None) -> dict:
    """Execute a contract-approved CTF-Rat tool with the role wall budget.

    The executable identity is pinned to ``CTF_HOME/bin``: an allowlisted
    basename alone is not sufficient to substitute an arbitrary lookalike.
    """
    if not isinstance(argv,list) or not argv or not all(isinstance(arg,str) and arg for arg in argv): raise GateError("broker command must be argv-only")
    tool=os.path.basename(argv[0]); authorize(contract,"tool-run",inputs=inputs,tool=tool,artifact_root=artifact_root)
    home=os.path.abspath(ctf_home or os.environ.get("CTF_HOME") or os.path.join(os.path.dirname(__file__),"..",".."))
    trusted=os.path.realpath(os.path.join(home,"bin",tool))
    if os.path.realpath(argv[0])!=trusted or not os.path.isfile(trusted): raise GateError("broker only executes the pinned CTF-Rat tool path")
    result=run([trusted,*argv[1:]],timeout_seconds=contract["budgets"]["wall_seconds"],spool_dir=os.path.join(os.path.abspath(artifact_root or os.path.join(os.getcwd(),".rat")),"tmp"),tool_version="rat-broker/v1")
    root=os.path.abspath(artifact_root or os.path.join(os.getcwd(),".rat"))
    artifacts=[]
    for label,captured in (("stdout",result.stdout),("stderr",result.stderr)):
        data=open(captured.spool_path,"rb").read() if captured.spool_path else captured.preview
        record=put_bytes(data,kind="broker-"+label,media_type="application/octet-stream",logical_name=label+".bin",root=root)
        artifacts.append({k:record[k] for k in ("digest","kind","media_type","size","logical_name")})
    return {"authorized":True,"tool":tool,"exit_code":result.exit_code,"timed_out":result.timed_out,"duration_ms":result.duration_ms,"artifacts":artifacts}

def main(argv=None):
    import argparse
    parser=argparse.ArgumentParser(prog="rat-broker")
    parser.add_argument("--contract",required=True)
    parser.add_argument("--root",default=os.path.join(os.getcwd(),".rat"))
    parser.add_argument("--action",required=True,choices=sorted(_ACTIONS))
    parser.add_argument("--input",action="append",default=[])
    parser.add_argument("--state-event")
    parser.add_argument("--tool")
    parser.add_argument("--run",nargs=__import__("argparse").REMAINDER,default=[])
    args=parser.parse_args(argv)
    try:
        with open(args.contract,encoding="utf-8") as source: contract=json.load(source)
        if args.run:
            if args.action!="tool-run": raise GateError("--run requires tool-run action")
            print(json.dumps(run_authorized(contract,args.run,inputs=args.input,artifact_root=args.root),sort_keys=True))
        else:
            print(json.dumps(authorize(contract,args.action,inputs=args.input,state_event=args.state_event,tool=args.tool,artifact_root=args.root),sort_keys=True))
        return 0
    except (OSError,ValueError,GateError,json.JSONDecodeError) as exc:
        print("[rat-broker:policy] %s" % exc, file=__import__("sys").stderr)
        return 5
