"""P2 bounded analysis executors.

These adapters deliberately report observations and candidates, never a solved
exploit.  They share one small envelope/artifact implementation so a later
tool consumes IDs/artifacts rather than a previous tool's terminal output.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, platform, re, shutil, sys, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from .artifact import put_bytes, put_file, digest_bytes, get, metadata
from .runner import run, EXIT_DEPENDENCY, EXIT_INPUT, EXIT_POLICY, EXIT_TIMEOUT

VERSION="p2-mvp/1"; POLICY="sha256:"+hashlib.sha256(b"p2-local-executable-only").hexdigest()
def _module_digest():
 # Content-addressed identity of the verdict logic itself (this file), so a
 # verification-report producer can be resolved by CONTENT the same way
 # state_v2 resolves SELF-evidence verifiers -- not by a fixed policy label
 # that any tool can copy into its own report.
 h=hashlib.sha256()
 with open(os.path.realpath(__file__),"rb") as f:
  for b in iter(lambda:f.read(65536),b""): h.update(b)
 return "sha256:"+h.hexdigest()
BUILD_DIGEST=_module_digest()
VERIFY_BUILD_DIGEST=BUILD_DIGEST
P2_LIMITATIONS={
 "rat-profile":["format signals are not vulnerability proof"],
 "rat-slice":["call-path reachability only; no value-flow proof"],
 "rat-dyn":["local execution trace; remote equivalence is unproven"],
 "rat-fuzz":["builtin corpus has no coverage guidance"],
 "rat-heap":["timeline requires complete allocator events"],
 "rat-rop":["gadget candidates are not exploit success"],
 "rat-runtime":["runtime backend coverage is incomplete"],
 "rat-vm":["toy VM semantics only unless executable oracle passes"],
 "rat-verify":["local verification does not establish remote equivalence"],
}
def iso(): return datetime.now(timezone.utc).isoformat()
def root(a, binary=None):
    # M2 rework: the canonical index + artifact store resolve through the one
    # shared resolver so rat-profile lands in the same sqlite as revq/decomp.
    # --store stays honored as an explicit override (back-compat); the default
    # (no --store) converges to dirname(binary)/.rat like the other two tools.
    from .cache import resolve_index_root
    return resolve_index_root(binary or getattr(a, "binary", None), override=getattr(a, "store", None))
def fdigest(p):
 h=hashlib.sha256()
 with open(p,"rb") as f:
  for b in iter(lambda:f.read(65536),b""): h.update(b)
 return "sha256:"+h.hexdigest()
def canonical_digest(value):
 raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
 return "sha256:"+hashlib.sha256(raw).hexdigest()
def profile_environment(a):
 return {"binary":fdigest(a.binary),
         "libc":fdigest(a.libc) if getattr(a,"libc",None) and os.path.isfile(a.libc) else None,
         "loader":fdigest(a.loader) if getattr(a,"loader",None) and os.path.isfile(a.loader) else None}
def execution_environment(profile, sc):
 return canonical_digest({"profile_environment":profile.get("environment",{}),
                          "argv":[str(x) for x in sc.get("argv",[])],
                          "cwd":sc.get("cwd"),
                          "env":{str(k):str(v) for k,v in sc.get("env",{}).items()}})
def artifact(data, kind, name, r, media="application/json"):
    rec=put_bytes(data if isinstance(data,bytes) else json.dumps(data,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(),kind=kind,media_type=media,logical_name=name,root=r)
    return {k:rec[k] for k in ("kind","digest","media_type","size","logical_name")}
def load_json_artifact(digest, r, kind):
    """Read an artifact by digest, never by a producer-owned local path."""
    if not digest:
        raise ValueError("%s artifact digest is required" % kind)
    try:
        return json.loads(get(digest,root=r))
    except Exception as exc:
        raise ValueError("invalid %s artifact: %s" % (kind, exc)) from exc
def require_profile(a, r):
    profile=load_json_artifact(a.profile,r,"profile")
    if profile.get("binary_digest") != fdigest(a.binary):
        raise ValueError("profile binary digest does not match current binary")
    return profile
def envelope(name, binary, a, summary, artifacts=(), status="ok", diagnostics=(), code=0, started=None):
    started=started or iso(); finished=iso(); bdig=fdigest(binary) if binary and os.path.isfile(binary) else "sha256:"+"0"*64
    doc={"schema":"rat.tool-result/v1","tool":{"name":name,"version":VERSION,"build_digest":BUILD_DIGEST},"run_id":"local","invocation_id":"invoke_"+uuid.uuid4().hex,"status":status,"started_at":started,"finished_at":finished,"duration_ms":max(0,int((datetime.fromisoformat(finished)-datetime.fromisoformat(started)).total_seconds()*1000)),"inputs":([{"role":"binary","digest":bdig,"size":os.path.getsize(binary)}] if binary and os.path.isfile(binary) else []),"parameters":{k:v for k,v in vars(a).items() if k not in {"binary","store","format","command"} and v is not None},"summary":summary,"artifacts":list(artifacts),"findings":[],"diagnostics":[{"code":"p2","severity":"warning" if status!="ok" else "info","message":x} for x in diagnostics],"exit":{"code":code,"signal":None,"timed_out":status=="timeout","cancelled":False},"provenance":{"platform":{"os":sys.platform,"arch":platform.machine()},"dependency_versions":{},"policy_digest":POLICY,"cache":{"key":None,"hit":False,"source_invocation":None}}}
    if name in P2_LIMITATIONS:
        # Analysis output is deliberately non-promotable.  Only STATE's
        # evidence/primitive lifecycle may promote independently verified
        # observations.
        doc["extensions"]={"analysis_policy":{"maturity":"experimental","promotion_allowed":False,"evidence_quality":"heuristic","limitations":P2_LIMITATIONS[name]}}
    return doc
def emit(doc,a):
    print(json.dumps(doc,sort_keys=True) if a.format=="json" else "%s: %s"%(doc["tool"]["name"],json.dumps(doc["summary"],ensure_ascii=False)))
    return doc["exit"]["code"]
def command(argv, timeout, stdin=None, cwd=None, env=None):
    return run(argv,timeout_seconds=timeout,input_bytes=stdin,cwd=cwd,env=env,tool_version=VERSION)
def scenario(path):
    if not path: return {}
    with open(path,encoding="utf-8") as f: s=json.load(f)
    if s.get("schema") not in (None,"rat.scenario/v1"): raise ValueError("unsupported scenario schema")
    return s
def scenario_stdin(sc):
    if "stdin" in sc and "stdin_base64" in sc: raise ValueError("scenario stdin encodings are mutually exclusive")
    if "stdin_base64" in sc:
        try: return base64.b64decode(sc["stdin_base64"],validate=True)
        except (ValueError,TypeError) as exc: raise ValueError("invalid scenario stdin_base64") from exc
    value=sc.get("stdin","")
    if not isinstance(value,str): raise ValueError("scenario stdin must be text")
    return value.encode()
def execute_binary(binary, sc, timeout):
    stdin=scenario_stdin(sc)
    argv=[binary]+[str(x) for x in sc.get("argv",[])]
    env={str(k):str(v) for k,v in sc.get("env",{}).items()}
    return command(argv,timeout,stdin=stdin,cwd=sc.get("cwd"),env=env)
def _profile_cache_keys(bdig, environment):
    from .cache import canonical_key
    return {k: canonical_key(binary_sha256=bdig,tool_name="rat-profile",tool_version=VERSION,
                              params={"artifact":k,"libc":environment.get("libc"),"loader":environment.get("loader")},
                              dep_versions={})
            for k in ("profile","string-index")}
def _profile_cache_lookup(r, bdig, environment):
    """Read-through the shared canonical index; miss on any inconsistency."""
    try:
        from .cache import Cache
        idx=Cache(r); keys=_profile_cache_keys(bdig,environment)
        pe,se=idx.get_entry(keys["profile"]),idx.get_entry(keys["string-index"])
        if not (pe and se): return idx,keys,None,None,None
        profile_doc=json.loads(get(pe["path"],root=r))
        if profile_doc.get("binary_digest")!=bdig: return idx,keys,None,None,None
        profile_art={k:metadata(pe["path"],root=r)[k] for k in ("kind","digest","media_type","size","logical_name")}
        strings_art={k:metadata(se["path"],root=r)[k] for k in ("kind","digest","media_type","size","logical_name")}
        return idx,keys,profile_doc,(profile_art,strings_art),pe.get("source_invocation")
    except Exception:
        return None,None,None,None,None
def profile(a):
    if not os.path.isfile(a.binary): return emit(envelope("rat-profile",a.binary,a,{},status="error",code=EXIT_INPUT,diagnostics=["binary missing"]),a)
    r=root(a,a.binary); started=iso(); bdig=fdigest(a.binary); environment=profile_environment(a)
    if getattr(a,"no_cache",False):
        keys=_profile_cache_keys(bdig,environment)
        try:
            from .cache import Cache
            idx=Cache(r)
        except Exception:
            idx=None
        cached_doc,cached_arts,src_inv=None,None,None
    else:
        idx,keys,cached_doc,cached_arts,src_inv=_profile_cache_lookup(r,bdig,environment)
    if cached_doc and cached_arts:
        cache_state="hit"; facts,signals,routes=cached_doc["facts"],cached_doc["signals"],cached_doc["routes"]
        arts=list(cached_arts)
    else:
        cache_state="miss"; facts=[]; signals=[]; routes=[]
        fileout=command(["file","--",a.binary],a.timeout).stdout.preview.decode(errors="replace").strip()
        readelf=command(["readelf","-hW","-lW","-sW",a.binary],a.timeout).stdout.preview.decode(errors="replace")
        is_elf=fileout.startswith("ELF ")
        facts.append({"kind":"format","value":fileout,"quality":"direct"})
        if is_elf:
            facts.extend([{"kind":"elf.pie","value":"DYN" in readelf,"quality":"direct"},{"kind":"elf.nx","value":"GNU_STACK" in readelf and "RWE" not in readelf,"quality":"direct"},{"kind":"elf.relro","value":"GNU_RELRO" in readelf,"quality":"direct"}])
        imports=re.findall(r"\b(?:UND\s+)?([_A-Za-z][\w@.]*)$",readelf,re.M)
        strings=command(["strings","-n","4","--",a.binary],a.timeout).stdout.preview.decode(errors="replace")
        for api in ("gets","strcpy","strcat","sprintf","memcpy","read","scanf"):
            if re.search(r"\b"+re.escape(api)+r"(?:@|\b)",readelf): signals.append({"detector":"dangerous-import/v1","target":api,"score":0.6,"false_positive_note":"import alone is not a vulnerability"})
        if signals: routes.append({"tool":"rat-slice","target":signals[0]["target"],"reason":"inspect direct call/data-flow before claim"})
        arts=[artifact({"binary_digest":bdig,"environment":environment,"facts":facts,"signals":signals,"routes":routes,"imports":imports},"profile","profile.json",r),artifact({"strings":strings.splitlines()[:1000]},"string-index","string-index.json",r)]
    is_elf=next((f["value"] for f in facts if f["kind"]=="format"),"").startswith("ELF ")
    coverage="elf-header+program-header+dynamic-symbols" if is_elf else "format-only; ELF protection facts skipped"
    doc=envelope("rat-profile",a.binary,a,{"format":next((f["value"] for f in facts if f["kind"]=="format"),""),"fact_count":len(facts),"signal_count":len(signals),"route_count":len(routes),"coverage":coverage,"skipped_analyzers":[] if is_elf else ["elf-protections"]},arts,started=started)
    doc["tool_name"]="rat-profile"; doc["params_digest"]=keys["profile"] if keys else "unindexed"; doc["cache_state"]=cache_state
    # Register on miss AFTER the envelope exists so this run's invocation_id is
    # recorded as the source of any later hit.
    if cache_state=="miss" and idx and keys:
        try:
            idx.put_entry(keys["profile"],backend="profile_artifact",path=arts[0]["digest"],source_invocation=doc["invocation_id"])
            idx.put_entry(keys["string-index"],backend="profile_artifact",path=arts[1]["digest"],source_invocation=doc["invocation_id"])
        except Exception: pass
    doc["provenance"]["cache"]={"key":keys["profile"] if keys else None,"hit":cache_state=="hit","source_invocation":src_inv if cache_state=="hit" else None}
    return emit(doc,a)
DATA_SLICE_INPUT_APIS={"read","fgets","gets","scanf","__isoc99_scanf","recv","getchar","fgetc"}
def _data_slice_locate_function(cfg,project,target):
    for func in cfg.kb.functions.values():
        for ba in func.block_addrs_set:
            try: size=project.factory.block(ba).size
            except Exception: continue
            if ba<=target<ba+size: return func
    return None
def _data_slice_scan_registers(project,func,target,max_blocks=16):
    """Bounded, best-effort register/stack-local/memory-load scan over this
    function's blocks at or before the target address (VEX pretty-print
    regex, not a real def-use graph -- a summary, not a proof)."""
    stack_reg_names={"rsp","rbp","esp","ebp","sp","bp"}
    def reg_name(offset):
        try: return project.arch.register_names.get(int(offset))
        except Exception: return None
    registers=set(); stack_local=False; loads=0; stack_loads=0
    blocks=sorted(b for b in func.block_addrs_set if b<=target)[-max_blocks:]
    for ba in blocks:
        try: irsb=project.factory.block(ba).vex
        except Exception: continue
        for stmt in irsb.statements:
            text=str(stmt)
            for off in re.findall(r"GET:\w+\(offset=(\d+)\)",text):
                name=reg_name(off)
                if name: registers.add(name)
            offsets_here=re.findall(r"(?:GET:\w+|PUT)\(offset=(\d+)\)",text)
            if any(reg_name(o) in stack_reg_names for o in offsets_here): stack_local=True
            if re.search(r"\bLD[bl]e:",text):
                loads+=1
                if any(reg_name(o) in stack_reg_names for o in offsets_here): stack_loads+=1
    return sorted(registers),stack_local,loads,(loads-stack_loads)
def _parse_addr(value):
    try: return int(value,0)
    except (TypeError,ValueError): return None
def _data_slice(a,r,started,profile):
    target=_parse_addr(a.backward_addr)
    if target is None:
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"data"},status="error",code=EXIT_INPUT,diagnostics=["--backward requires an address"],started=started),a)
    try:
        import angr
        project=angr.Project(a.binary,auto_load_libs=False); cfg=project.analyses.CFGFast(normalize=True)
        func=_data_slice_locate_function(cfg,project,target)
        if func is None:
            return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"data","coverage":"incomplete"},status="partial",diagnostics=["target address not found in any recovered function"],started=started),a)
        registers,stack_local,loads,unresolved_aliases=_data_slice_scan_registers(project,func,target)
        callgraph=cfg.kb.functions.callgraph
        def callee_names(addr):
            return sorted({cfg.kb.functions[n].name for n in callgraph.successors(addr) if n in cfg.kb.functions}) if addr in callgraph else []
        direct_calls=callee_names(func.addr)
        input_calls=sorted(set(direct_calls)&DATA_SLICE_INPUT_APIS)
        depth_budget=max(0,min(int(a.depth or 0),2))
        callers_by_depth={}
        frontier={func.addr}; seen={func.addr}
        for d in range(1,depth_budget+1):
            nxt=set()
            for addr in frontier:
                if addr in callgraph:
                    nxt |= {p for p in callgraph.predecessors(addr) if p in cfg.kb.functions and p not in seen}
            if not nxt: break
            callers_by_depth[d]=sorted(cfg.kb.functions[n].name for n in nxt)
            seen |= nxt; frontier=nxt
        unresolved_indirect=1 if getattr(func,"has_unresolved_calls",False) else 0
        payload={
            "analysis_kind":"data","source":a.source,
            "target":{"address":"%#x"%target,"function":func.name},
            "within_function":{"registers_read":registers,"stack_locals_referenced":stack_local,
                                 "direct_calls":direct_calls,"input_api_calls":input_calls},
            "interproc":{"depth":depth_budget,"callers_by_depth":callers_by_depth},
            "claim":"dependency-candidate",
            "unresolved_aliases":unresolved_aliases,"unresolved_indirect_calls":unresolved_indirect,
        }
        diagnostics=["backward data slice is a bounded VEX-text summary, not a proven def-use graph",
                     "heap/global aliasing and indirect calls are not resolved; see unresolved_* counts"]
        return emit(envelope("rat-slice",a.binary,a,payload,status="ok",diagnostics=diagnostics,started=started),a)
    except Exception as exc:
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"data","coverage":"incomplete"},status="partial",diagnostics=["angr analysis incomplete: %s"%type(exc).__name__],started=started),a)
def slice_(a):
    r=root(a,a.binary); started=iso()
    try: profile=require_profile(a,r)
    except ValueError as exc: return emit(envelope("rat-slice",a.binary,a,{},status="error",code=EXIT_INPUT,diagnostics=[str(exc)],started=started),a)
    # Input-contract validation is independent of angr availability: a malformed
    # request is a usage error whether or not the analysis engine is present.
    mode=getattr(a,"mode","call-path")
    if mode=="data" and _parse_addr(a.backward_addr) is None:
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"data"},status="error",code=EXIT_INPUT,diagnostics=["--backward requires an address"],started=started),a)
    if mode!="data" and not a.from_loc:
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"call-path"},status="error",code=EXIT_INPUT,diagnostics=["--from is required in call-path mode"],started=started),a)
    try:
        import angr
    except ImportError:
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":mode,"coverage":"unavailable"},status="partial",diagnostics=["angr dependency missing; no synthetic slice emitted"],started=started),a)
    if mode=="data":
        return _data_slice(a,r,started,profile)
    try:
        project=angr.Project(a.binary,auto_load_libs=False); cfg=project.analyses.CFGFast(normalize=True)
        funcs=list(cfg.kb.functions.values())
        def locate(value):
            needle=value.lower().replace("@plt","")
            for f in funcs:
                if f.name.lower().replace("@plt","")==needle: return f
            try: address=int(value,0)
            except ValueError: return None
            return cfg.kb.functions.get(address)
        src, sink=locate(a.from_loc), locate(a.to_loc) if a.to_loc else None
        nodes=[]; edges=[]; paths=[]
        if src:
            nodes.append({"id":"%#x"%src.addr,"address":"%#x"%src.addr,"function":src.name})
        if src and sink:
            import networkx as nx
            try: paths=[nx.shortest_path(cfg.functions.callgraph,src.addr,sink.addr)][:1]
            except (nx.NetworkXNoPath, nx.NodeNotFound): paths=[]
            for path in paths:
                for addr in path:
                    f=cfg.kb.functions.get(addr)
                    ir_blocks=[]
                    if f:
                        for block_addr in list(f.block_addrs_set)[:max(1,a.depth)]:
                            try:
                                vex=project.factory.block(block_addr).vex
                                ir_blocks.append({"address":"%#x"%block_addr,"vex_statements":len(vex.statements),"jumpkind":vex.jumpkind})
                            except Exception: pass
                    node={"id":"%#x"%addr,"address":"%#x"%addr,"function":f.name if f else "unknown","ir_blocks":ir_blocks}
                    if node not in nodes: nodes.append(node)
                edges += [{"from":"%#x"%x,"to":"%#x"%y,"kind":"cfg.call","quality":"direct"} for x,y in zip(path,path[1:])]
        unresolved=sum(1 for f in funcs if getattr(f,"has_unresolved_calls",False))
        payload={"binary_digest":fdigest(a.binary),"profile_digest":a.profile,"nodes":nodes,"edges":edges,"unresolved_indirect_edges":unresolved,"frontier":[]}
        arts=[artifact(payload,"static-slice","slice.json",r)]
        status="ok" if paths else "partial"
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"call-path","nodes":len(nodes),"edges":len(edges),"sources_reached":bool(src),"sinks_reached":bool(sink and paths),"coverage":"angr CFGFast callgraph + VEX IR blocks","unresolved_indirect_edges":unresolved,"path_count":len(paths)},arts,status=status,diagnostics=(["no CFG call path; no data-flow claim made"] if not paths else ["call-path reachability is not a data-flow proof"]),started=started),a)
    except Exception as exc:
        return emit(envelope("rat-slice",a.binary,a,{"analysis_kind":"call-path","coverage":"incomplete"},status="partial",diagnostics=["angr analysis incomplete: %s"%type(exc).__name__],started=started),a)
def dyn(a):
    r=root(a,a.binary); started=iso()
    try: profile=require_profile(a,r)
    except ValueError as exc: return emit(envelope("rat-dyn",a.binary,a,{},status="error",code=EXIT_INPUT,diagnostics=[str(exc)],started=started),a)
    sc=scenario(a.scenario); p=execute_binary(a.binary,sc,a.timeout)
    out=p.stdout.preview; err=p.stderr.preview; events=[{"event":"process.exit","exit_code":p.exit_code,"signal":p.signal,"timed_out":p.timed_out}]
    registers={}
    # GDB is optional.  A requested breakpoint is either observed structurally
    # or reported as dependency-missing/partial; we never invent registers.
    if a.break_loc:
        if shutil.which("gdb"):
            # The debugger observation must exercise the same invocation as
            # the ordinary trace; otherwise a breakpoint hit is not evidence
            # about the scenario that produced the trace artifact.
            gp=command(["gdb","-q","-nx","-batch","-ex","break "+a.break_loc,"-ex","run","-ex","info registers","--args",a.binary,*[str(x) for x in sc.get("argv",[])]],a.timeout,stdin=scenario_stdin(sc),cwd=sc.get("cwd"),env={str(k):str(v) for k,v in sc.get("env",{}).items()})
            gtext=(gp.stdout.preview+gp.stderr.preview).decode(errors="replace")
            for key,val in re.findall(r"\b([a-z]{2,3})\s+0x([0-9a-f]+)",gtext): registers[key]="0x"+val
            events.append({"event":"breakpoint","location":a.break_loc,"hit":bool(registers),"registers":registers})
        else:
            events.append({"event":"breakpoint","location":a.break_loc,"hit":False,"reason":"gdb dependency missing"})
    for marker in sc.get("markers",[]):
        events.append({"event":"marker","marker":marker,"observed":marker.encode() in out+err})
    status="timeout" if p.timed_out else ("ok" if p.exit_code==0 else "partial")
    arts=[artifact({"binary_digest":fdigest(a.binary),"profile_digest":a.profile,"environment_digest":execution_environment(profile,sc),"scope":"local-only","events":events},"execution-trace","trace.json",r),artifact(out,"io-transcript","stdout.bin",r,"application/octet-stream"),artifact(err,"io-transcript","stderr.bin",r,"application/octet-stream")]
    return emit(envelope("rat-dyn",a.binary,a,{"exit":p.exit_code,"signal":p.signal,"trace_span":len(events),"hit_counts":{"breakpoint":int(any(e["event"]=="breakpoint" and e.get("hit") for e in events))},"register_observations":len(registers),"memory_observations":0,"last_event":events[-1]["event"],"dropped_events":0,"scenario_step":sc.get("name","run")},arts,status=status,diagnostics=(["wall timeout; last stable event retained"] if p.timed_out else []),code=p.exit_code if not p.timed_out else EXIT_TIMEOUT,started=started),a)
def _verify_conditions(expected, process, scenario_doc):
    if "exit_code" in expected and process.exit_code != expected["exit_code"]: return False
    if "stdout_regex" in expected and not re.search(expected["stdout_regex"], process.stdout.preview.decode(errors="replace")): return False
    if "stderr_regex" in expected and not re.search(expected["stderr_regex"], process.stderr.preview.decode(errors="replace")): return False
    if "file_digests" in expected:
        files=expected["file_digests"]
        base=Path(scenario_doc.get("cwd") or os.getcwd()).resolve()
        if not isinstance(files,dict) or not files: return False
        for name,digest in files.items():
            if not isinstance(name,str) or not isinstance(digest,str): return False
            candidate=(base / name).resolve()
            if (candidate != base and base not in candidate.parents) or not candidate.is_file() or fdigest(candidate)!=digest: return False
    return not process.timed_out

def _strict_expect(scenario_doc):
    """Validate the executable oracle shared by verify and VM lifting."""
    expected=scenario_doc.get("expect",{})
    allowed={"exit_code","stdout_regex","stderr_regex","file_digests"}
    if not isinstance(expected,dict) or not expected:
        raise ValueError("executable oracle requires a non-empty expect condition")
    if set(expected)-allowed:
        raise ValueError("unsupported verification condition")
    return expected

def _oracle_argv(spec):
    """Accept an executable or a JSON argv array; never invoke a shell."""
    if not spec: return None
    if spec.lstrip().startswith("["):
        argv=json.loads(spec)
        if not isinstance(argv,list) or not argv or not all(isinstance(x,str) and x for x in argv):
            raise ValueError("oracle JSON must be a non-empty argv array")
        return argv
    return [spec]

def verify(a):
    r=root(a,a.binary); started=iso()
    try:
        profile=require_profile(a,r); trace=load_json_artifact(a.trace,r,"execution trace")
        if trace.get("binary_digest") != fdigest(a.binary): raise ValueError("trace binary digest does not match current binary")
    except ValueError as exc: return emit(envelope("rat-verify",a.binary,a,{},status="error",code=EXIT_INPUT,diagnostics=[str(exc)],started=started),a)
    sc=scenario(a.scenario); reps=max(1,a.runs); results=[]; expected=sc.get("expect",{})
    try:
        oracle_argv=_oracle_argv(a.oracle)
        if not expected and not oracle_argv: raise ValueError("verification requires scenario expect or --oracle")
        if expected: _strict_expect(sc)
        if not all(isinstance(getattr(a,key),str) and getattr(a,key) for key in ("claim","primitive","exploit_task")): raise ValueError("verification PASS provenance requires --claim, --primitive, and --exploit-task")
    except (ValueError,json.JSONDecodeError) as exc:
        return emit(envelope("rat-verify",a.binary,a,{},status="error",code=EXIT_POLICY,diagnostics=[str(exc)],started=started),a)
    environment_match=trace.get("environment_digest")==execution_environment(profile,sc)
    for _ in range(reps):
        p=execute_binary(a.binary,sc,a.timeout); ok=_verify_conditions(expected,p,sc) if expected else True; oracle_result=None
        if oracle_argv:
            payload={"schema":"rat.verification-oracle-input/v1","binary_digest":fdigest(a.binary),"environment_digest":execution_environment(profile,sc),"exit_code":p.exit_code,"timed_out":p.timed_out,"stdout":p.stdout.preview.decode(errors="replace"),"stderr":p.stderr.preview.decode(errors="replace")}
            oracle=command(oracle_argv,a.timeout,stdin=json.dumps(payload,sort_keys=True).encode())
            oracle_result={"argv":oracle.argv,"exit":oracle.exit_code,"timed_out":oracle.timed_out,"stdout":oracle.stdout.preview.decode(errors="replace"),"stderr":oracle.stderr.preview.decode(errors="replace")}
            oracle_result["artifact"]=artifact(oracle_result,"verification-oracle","oracle.json",r)["digest"]
            ok=ok and not oracle.timed_out and oracle.exit_code==0
        results.append({"exit":p.exit_code,"timed_out":p.timed_out,"conditions_met":ok,"oracle":oracle_result})
    verdict="pass" if environment_match and all(x["conditions_met"] for x in results) else ("inconclusive" if not environment_match or any(x["timed_out"] for x in results) else "fail")
    status="ok" if verdict=="pass" else ("timeout" if verdict=="inconclusive" else "partial")
    report={"schema":"rat.verification-report/v1","verdict":verdict,"repetitions":reps,"environment_match":environment_match,"scope":"local-only","provenance":{"claim_id":a.claim,"primitive_id":a.primitive,"exploit_task_id":a.exploit_task,"trace_digest":a.trace,"environment_digest":execution_environment(profile,sc)},"results":results,"producer":{"tool":"rat-verify","build_digest":VERIFY_BUILD_DIGEST}}
    arts=[artifact(report,"verification-report","verification.json",r)]
    diagnostics=[]
    if not environment_match: diagnostics.append("trace environment does not match this verification scenario")
    if verdict!="pass": diagnostics.append("only pass may support confirmed finding or primitive PASS")
    return emit(envelope("rat-verify",a.binary,a,{"verdict":verdict,"repetitions":reps,"environment_match":environment_match,"scope":"local-only","failed_conditions":[i for i,x in enumerate(results) if not x["conditions_met"]]},arts,status=status,diagnostics=diagnostics,code=0 if verdict=="pass" else (EXIT_TIMEOUT if verdict=="inconclusive" else 1),started=started),a)
def fuzz(a):
    r=root(a,a.binary); started=iso(); corpus=[]
    if a.corpus and os.path.isdir(a.corpus): corpus=[Path(a.corpus,x).read_bytes() for x in os.listdir(a.corpus) if os.path.isfile(Path(a.corpus,x))]
    corpus=corpus or [b"",b"A",b"A"*16,b"A"*128]; deadline=time.monotonic()+a.budget; crashes={}; non_crash_exits={}; runs=0
    while time.monotonic()<deadline:
        data=corpus[runs%len(corpus)]; p=command([a.binary],min(a.timeout,max(.01,deadline-time.monotonic())),stdin=data); runs+=1
        if p.signal and not p.timed_out:
            sig="signal:%s"%p.signal
            # A unique failure remains a proposed signal unless the exact
            # testcase reproduces three times under the same local scenario.
            reproduced=0
            for _ in range(3):
                remaining=deadline-time.monotonic()
                if remaining<=0: break
                q=command([a.binary],min(a.timeout,max(.01,remaining)),stdin=data)
                reproduced += int(q.exit_code == p.exit_code and not q.timed_out)
            if reproduced == 3: crashes.setdefault(sig,data)
        elif p.exit_code and not p.timed_out:
            non_crash_exits.setdefault("exit:%s"%p.exit_code,0); non_crash_exits["exit:%s"%p.exit_code]+=1
    arts=[artifact({"execs":runs,"crashes":list(crashes),"non_crash_exits":non_crash_exits},"fuzz-corpus","fuzz.json",r)]+[artifact(v,"crash-input","crash-%s.bin"%i,r,"application/octet-stream") for i,v in enumerate(crashes.values())]
    return emit(envelope("rat-fuzz",a.binary,a,{"execs":runs,"coverage":"unavailable without optional engine","unique_crash":len(crashes),"unique_hang":0,"non_crash_exit":non_crash_exits,"corpus_delta":0},arts,status="partial",diagnostics=["budget exhaustion is a normal partial result; only reproduced signal exits are crash candidates"],started=started),a)
def heap(a):
    r=root(a,a.binary); started=iso(); trace=json.load(open(a.trace,encoding="utf-8")) if a.trace else scenario(a.scenario); events=trace.get("events",[]); violations=[]
    for e in events:
        if all(k in e for k in ("chunk","target","encoded_fd")) and e["encoded_fd"] != (e["target"] ^ (e["chunk"]>>12)): violations.append("safe-linking mismatch")
    arts=[artifact({"events":events,"violations":violations},"heap-timeline","heap.json",r)]
    return emit(envelope("rat-heap",a.binary,a,{"allocator":trace.get("allocator","unknown"),"event_count":len(events),"bin_count":len(trace.get("bins",{})),"invariant_violations":violations,"ambiguity":trace.get("gaps",[])},arts,status="partial" if trace.get("gaps") else "ok",diagnostics=(["trace gap makes crossing invariants unknown"] if trace.get("gaps") else []),started=started),a)
def rop(a):
    r=root(a,a.binary); started=iso(); p=command(["objdump","-d","--",a.binary],a.timeout); gadgets=[x.strip() for x in p.stdout.preview.decode(errors="replace").splitlines() if re.search(r"\b(ret|pop\s+%rdi)",x)]
    # A name is not proof.  Exploit-oriented ROP consumes only an active P1
    # primitive PASS from the local state stream.
    active = bool(a.index_only)
    if not a.index_only and a.primitive and a.input_digest and a.environment_digest:
        try:
            from .state_v2 import Stream
            prim = Stream(os.path.dirname(r)).view()["primitives"].get(a.primitive, {})
            active = (a.input_digest == fdigest(a.binary) and prim.get("status") == "pass"
                      and prim.get("input_digest") == a.input_digest
                      and prim.get("environment_digest") == a.environment_digest)
        except Exception:
            active = False
    blocked=not active; status="error" if blocked else "ok"; code=EXIT_POLICY if blocked else 0
    arts=[artifact({"gadgets":gadgets[:500],"goal":a.goal,"candidate_is_not_exploit_success":True},"gadget-index","gadgets.json",r)]
    diagnostic="index-only artifacts cannot be promoted" if a.index_only else ("active verified primitive, input digest, and environment digest required for exploit-oriented mode" if blocked else "candidates require verify")
    return emit(envelope("rat-rop",a.binary,a,{"gadget_count":len(gadgets),"goal":a.goal,"index_only":a.index_only,"candidate_count":0 if blocked else len(gadgets),"constraints":{"alignment":"not proven","bad_bytes":"not assessed"}},arts,status=status,diagnostics=[diagnostic],code=code,started=started),a)
def runtime(a):
    r=root(a,a.binary); started=iso(); sc=scenario(a.scenario)
    backend=a.backend
    if backend=="qiling":
        if not a.rootfs or not os.path.isdir(a.rootfs):
            return emit(envelope("rat-runtime",a.binary,a,{"backend":backend,"unsupported":"rootfs missing"},status="partial",diagnostics=["Qiling requires an explicit rootfs; no host fallback"],started=started),a)
        adapter=os.path.join(os.path.dirname(os.path.dirname(__file__)),"rat-qiling")
        q=command([adapter,a.binary,"--rootfs",a.rootfs,"--timeout",str(a.timeout)],a.timeout+1)
        return emit(envelope("rat-runtime",a.binary,a,{"backend":backend,"guest_arch":"unknown","environment_digest":fdigest(a.binary),"exit":q.exit_code,"syscall_coverage":"qiling adapter"},[artifact(q.stdout.preview,"runtime-manifest","qiling.json",r,"application/json")],status="ok" if q.exit_code==0 else "partial",diagnostics=(["qiling adapter returned partial"] if q.exit_code else []),code=q.exit_code,started=started),a)
    if backend=="qemu":
        qemu=shutil.which("qemu-x86_64")
        if not qemu:
            return emit(envelope("rat-runtime",a.binary,a,{"backend":backend,"unsupported":"qemu-x86_64 dependency missing"},status="partial",diagnostics=["install qemu-user"],started=started),a)
        stdin=scenario_stdin(sc); p=command([qemu,a.binary,*[str(x) for x in sc.get("argv",[])]],a.timeout,stdin=stdin,cwd=sc.get("cwd"),env={str(k):str(v) for k,v in sc.get("env",{}).items()})
    else:
        p=execute_binary(a.binary,sc,a.timeout)
    arts=[artifact({"backend":backend,"exit":p.exit_code,"binary_digest":fdigest(a.binary)},"runtime-manifest","runtime.json",r)]
    return emit(envelope("rat-runtime",a.binary,a,{"backend":backend,"guest_arch":platform.machine(),"environment_digest":fdigest(a.binary),"exit":p.exit_code,"syscall_coverage":"unavailable"},arts,status="timeout" if p.timed_out else "ok",code=EXIT_TIMEOUT if p.timed_out else p.exit_code,started=started),a)
def vm(a):
    r=root(a,a.binary); started=iso(); code=Path(a.bytecode).read_bytes() if a.bytecode else b""; spec={1:1,2:0,3:0,4:0,5:1,255:0}; unknown=[]; ops=[]; pc=0
    while pc < len(code):
        op=code[pc]; ops.append(op)
        if op not in spec: unknown.append(hex(op)); pc+=1
        else: pc += 1+spec[op]
    candidate=b""; pc=0
    # Small, explicitly labelled differential lift for the documented toy VM:
    # INP; PUSH key; XOR; CMP target. Unknown semantics never produce input.
    while pc+5 < len(code) and code[pc:pc+1]==b"\x02" and code[pc+1:pc+2]==b"\x01" and code[pc+3:pc+5]==b"\x03\x05":
        candidate += bytes([code[pc+2]^code[pc+5]]); pc += 6
    verified=False
    if a.solve and candidate and a.oracle:
        try:
            oracle=scenario(a.oracle); oracle["stdin"]=candidate.decode("latin1")
            p=execute_binary(a.binary,oracle,a.timeout); expected=oracle.get("expect",{})
            verified=_verify_conditions(_strict_expect(oracle),p,oracle)
        except (OSError,ValueError): verified=False
    ops=sorted(set(ops)); candidates=[{"input_hex":candidate.hex(),"verified":verified}] if candidate and verified else []
    arts=[artifact({"opcodes":ops,"unknown":unknown,"dispatch":a.dispatch,"derived_candidate_hex":candidate.hex() if candidate else None,"candidate_verified":verified},"opcode-table","opcodes.json",r)]
    status="partial" if unknown or (a.solve and candidate and not verified) else "ok"
    diagnostics=[]
    if a.solve and candidate and not verified: diagnostics.append("candidate withheld: executable oracle did not pass")
    return emit(envelope("rat-vm",a.binary,a,{"dispatcher_confidence":0.0 if not a.dispatch else 0.5,"opcode_count":len(ops),"lifted_count":1 if candidate else 0,"unknown_opcode":unknown,"solve_candidates":candidates},arts,status=status,diagnostics=diagnostics,started=started),a)
def parser():
    p=argparse.ArgumentParser(); p.add_argument("binary"); p.add_argument("--timeout",type=float,default=5); p.add_argument("--max-output",type=int,default=65536); p.add_argument("--format",choices=("text","json"),default="text"); p.add_argument("--store"); p.add_argument("--no-cache",action="store_true"); return p
_DIGEST_HANDOFF_EPILOG = (
    "P2 digest handoff: --profile/--trace take an artifact DIGEST, not a path.\n"
    "Get the profile digest first, then feed it in:\n"
    "  PROFILE=$(rat-profile \"$BIN\" --format json | jq -r .artifacts[0].digest)\n"
    "  rat-dyn \"$BIN\" --profile \"$PROFILE\" --scenario scen.json\n"
    "rat-verify additionally needs the rat-dyn trace digest:\n"
    "  TRACE=$(rat-dyn \"$BIN\" --profile \"$PROFILE\" --scenario scen.json --format json | jq -r '.artifacts[]|select(.kind==\"execution-trace\").digest')\n"
    "  rat-verify \"$BIN\" --profile \"$PROFILE\" --trace \"$TRACE\" --scenario scen.json --oracle scen.json"
)
def main(which, argv=None):
    p=parser()
    if which in ("rat-dyn","rat-verify"):
        p.epilog=_DIGEST_HANDOFF_EPILOG; p.formatter_class=argparse.RawDescriptionHelpFormatter
    if which=="rat-profile": p.add_argument("--libc"); p.add_argument("--loader"); fn=profile
    elif which=="rat-slice": p.add_argument("--profile",required=True); p.add_argument("--from",dest="from_loc"); p.add_argument("--to",dest="to_loc"); p.add_argument("--direction",default="forward"); p.add_argument("--depth",type=int,default=4); p.add_argument("--mode",choices=["call-path","data"],default="call-path"); p.add_argument("--backward",dest="backward_addr"); p.add_argument("--source",default=None); fn=slice_
    elif which=="rat-dyn": p.add_argument("--profile",required=True); p.add_argument("--scenario",required=True); p.add_argument("--break",dest="break_loc"); p.add_argument("--watch"); fn=dyn
    elif which=="rat-verify": p.add_argument("--profile",required=True); p.add_argument("--trace",required=True); p.add_argument("--scenario",required=True); p.add_argument("--claim"); p.add_argument("--primitive"); p.add_argument("--exploit-task"); p.add_argument("--oracle"); p.add_argument("--runs",type=int,default=3); fn=verify
    elif which=="rat-fuzz": p.add_argument("--harness"); p.add_argument("--budget",type=float,default=.2); p.add_argument("--corpus"); p.add_argument("--engine",default="builtin"); fn=fuzz
    elif which=="rat-heap": p.add_argument("--scenario"); p.add_argument("--trace"); p.add_argument("--libc"); fn=heap
    elif which=="rat-rop": p.add_argument("--goal"); p.add_argument("--constraints"); p.add_argument("--primitive"); p.add_argument("--input-digest"); p.add_argument("--environment-digest"); p.add_argument("--index-only",action="store_true"); fn=rop
    elif which=="rat-runtime": p.add_argument("--backend",choices=("native","qemu","qiling"),default="native"); p.add_argument("--scenario",required=True); p.add_argument("--rootfs"); fn=runtime
    else: p.add_argument("--dispatch"); p.add_argument("--trace"); p.add_argument("--bytecode"); p.add_argument("--solve",action="store_true"); p.add_argument("--oracle"); fn=vm
    a=p.parse_args(argv); return fn(a)