"""Deterministic, non-ranking Router v2."""
from __future__ import annotations
import re
from ratlib.evasion import SIGNAL_SCHEMA as EVASION_SIGNAL_SCHEMA

HEAP={"malloc","free","calloc","realloc"}; STRONG={"gets","strcpy","strcat","sprintf","scanf","__isoc99_scanf","__isoc99_sscanf"}
OVERFLOW=STRONG|{"read","memcpy","fgets","fread"}; FORMAT={"printf","fprintf","dprintf","syslog"}; INPUT={"read","gets","scanf","fgets"}
KERNEL={"copy_from_user","copy_to_user","kmalloc","kfree","module_init","module_exit"}; VM=("vm","opcode","bytecode","dispatch","interpreter")
CRYPTO=("aes","des","rc4","md5","sha","base64","xor","rsa","hmac","crc")
COMPARE={"strcmp","strncmp","memcmp","strcasecmp","strncasecmp","strstr","strcoll","bcmp","wcscmp","wcsncmp"}
SUCCESS=re.compile(r"correct|success|granted|accept(?:ed)?|congrat|nice|good\s*job|unlock|welcome|\bvalid\b|flag\{",re.I)
FAILURE=re.compile(r"incorrect|wrong|denied|reject(?:ed)?|invalid|fail(?:ed|ure)?|try\s*again",re.I)
DIMS=("vulnerability_surfaces","program_shapes","obstacles","constraints")
STRONG_OVERFLOW_IMPORTS=STRONG
WEAK_OVERFLOW_IMPORTS=OVERFLOW-STRONG
SKILLS={"rev-checker","rev-vm","rev-packed","rev-symbolic","pwn-stack","pwn-format","pwn-heap","pwn-rop","pwn-kernel"}

def _fact(profile,kind,default=None):
    return next((f.get("value") for f in (profile or {}).get("facts",[]) or [] if f.get("kind")==kind),default)
def _func(revq,name):
    return next((f for f in (revq or {}).get("functions",[]) or [] if isinstance(f,dict) and f.get("name")==name),None)
def _calls(revq,name):
    return {c.split("@",1)[0] for c in (_func(revq,name) or {}).get("calls",[]) or [] if isinstance(c,str) and c}
def _oracle(revq,name):
    strings=[s for s in (_func(revq,name) or {}).get("strings",[]) or [] if isinstance(s,str)]
    good=sorted({s for s in strings if SUCCESS.search(s)}); bad=sorted({s for s in strings if FAILURE.search(s)})
    return ({"success_count":len(good),"failure_count":len(bad),"success":good[:2],"failure":bad[:2]} if good and bad else None)
def _blob(revq):
    return " ".join(s.get("val","") for s in (revq or {}).get("strings",[]) or [] if isinstance(s,dict)).lower()
def _add(items,value):
    if value not in items: items.append(value)
def _sig(items,kind,value,quality):
    item={"kind":kind,"value":value,"quality":quality}
    if item not in items: items.append(item)
def _action(query,target,evidence,rule):
    return {"query":query,"target":target,"evidence":sorted(set(evidence)),"rule":rule}

def route(*,profile=None,revq=None,interesting=None):
    """Project observations and choose an action; never choose a challenge class."""
    imports=set((profile or {}).get("imports",[]) or [])|set((revq or {}).get("imports",[]) or [])
    dimensions={name:[] for name in DIMS}; signals=[]; unresolved=[]; leads=[]; actions=[]
    capabilities={"profile":profile is not None,"revq":revq is not None}; is_pe=(revq or {}).get("platform")=="pe"
    if is_pe:
        _sig(signals,"pe-platform","PE/Windows","fact"); _add(dimensions["constraints"],"pe-windows")
        actions.append(_action("solve/_template/rev/qiling_trace.py","pe-dynamic-emulation-rootfs-required",["pe-platform"],"PE execution requires the bounded Windows emulation path"))
    typed=(revq or {}).get("evasion_signals",[]) if (revq or {}).get("evasion_signal_schema")==EVASION_SIGNAL_SCHEMA else []
    packing=next((s for s in typed if isinstance(s,dict) and s.get("kind")=="packer-section" and s.get("quality")=="fact"),None)
    packing=packing or next((s for s in typed if isinstance(s,dict) and s.get("kind")=="high-entropy" and s.get("quality")=="heuristic"),None)
    if packing:
        _sig(signals,packing["kind"],packing.get("value"),packing["quality"]); _add(dimensions["obstacles"],"packing"); _add(leads,"packing")
        _add(unresolved,"packing is an analysis obstacle; the underlying program shape remains open")
        actions.append(_action("gdbq","verify-packer-and-unpack-need-before-dynamic-tracing",[packing["kind"]],"typed packing evidence requires confirmation"))
    hits=sorted(imports&KERNEL)
    if hits and not is_pe:
        _sig(signals,"kernel-imports",hits,"fact"); _add(dimensions["program_shapes"],"kernel-candidate"); _add(leads,"kernel")
        _add(unresolved,"kernel imports do not prove a kernel artifact or target environment")
        actions.append(_action("rat query pwn","confirm-kernel-artifact-and-environment-before-kernel-tooling",["kernel-imports"],"kernel tooling requires environment confirmation"))
    hits=sorted(imports&HEAP)
    if hits:
        _sig(signals,"heap-imports",hits,"fact"); _add(dimensions["vulnerability_surfaces"],"heap-lifetime-candidate"); _add(leads,"heap-lifetime")
        _add(unresolved,"allocator imports do not prove attacker-controlled lifetime, reuse, or overlap")
        if not is_pe:
            actions.append(_action("rat query pwn","inspect-bounded-allocator-callsites-and-lifetimes",["heap-imports"],"allocator use calls for bounded lifetime inspection"))
    fh,ih=sorted(imports&FORMAT),sorted(imports&INPUT)
    if fh and ih:
        _sig(signals,"format-input-imports",sorted(set(fh+ih)),"fact"); _add(dimensions["vulnerability_surfaces"],"format-string-candidate"); _add(leads,"format-string")
        _add(unresolved,"prove attacker control reaches a format argument")
        if not is_pe:
            actions.append(_action("rat query pwn","inspect-bounded-format-callsites-before-runtime-probe",["format-input-imports"],"format and input imports justify callsite inspection"))
    hits=sorted(imports&OVERFLOW)
    if hits:
        _sig(signals,"overflow-imports",hits,"fact" if imports&STRONG else "heuristic"); _add(dimensions["vulnerability_surfaces"],"stack-overwrite-candidate"); _add(leads,"stack-overwrite")
        _add(unresolved,"prove a concrete overwrite or PC-control primitive; import presence is insufficient")
        if _fact(profile,"elf.nx") is True: _sig(signals,"elf-nx",True,"fact"); _add(dimensions["constraints"],"nx")
        if not is_pe:
            actions.append(_action("rat query pwn","inspect-bounded-input-callsite-then-measure-overwrite",["overflow-imports"],"an input sink requires callsite inspection before a crash probe"))
    checker=[]
    for item in interesting or []:
        if not isinstance(item,dict) or not _func(revq,item.get("func")): continue
        name=item["func"]; compares=sorted(_calls(revq,name)&COMPARE); oracle=_oracle(revq,name)
        if compares or oracle:
            checker.append(name); _sig(signals,"checker-function",{"func":name},"heuristic")
            if compares: _sig(signals,"compare-calls",{"func":name,"calls":compares},"fact")
            if oracle: _sig(signals,"checker-oracle-strings",{"func":name,**oracle},"heuristic")
    if checker:
        _add(dimensions["program_shapes"],"checker"); _add(leads,"checker"); _add(unresolved,"checker semantics and success/failure oracle remain unverified")
        target=sorted(set(checker))[0]; actions.append(_action("rat query func",target,["checker-function"],"structured checker evidence supplies a concrete function target"))
    names=" ".join(f.get("name","") for f in (revq or {}).get("functions",[]) or [] if isinstance(f,dict)).lower(); blob=_blob(revq)
    vh=sorted({h for h in VM if h in names or h in blob})
    if vh:
        _sig(signals,"vm-dispatch-hint",vh,"heuristic"); _add(dimensions["program_shapes"],"vm-candidate"); _add(leads,"vm"); _add(unresolved,"VM hints do not prove a dispatch loop or bytecode semantics")
        actions.append(_action("solve/_template/rev/vmlift.py --disasm","prove-dispatch-loop-before-vm-lift",["vm-dispatch-hint"],"VM hints require dispatch-loop confirmation"))
    ch=sorted({h for h in CRYPTO if h in blob})
    if ch or (interesting and not checker):
        if ch: _sig(signals,"crypto-hint",ch,"heuristic")
        _add(dimensions["program_shapes"],"oracle-needed"); _add(leads,"oracle-discovery"); _add(unresolved,"a success/failure oracle must be bounded before symbolic execution")
        actions.append(_action("rat query oracle","success-failure-oracle-before-symbolic",["crypto-hint"] if ch else [],"interesting code requires an oracle before symbolic execution"))
    priority={"rat query func":0,"solve/_template/rev/qiling_trace.py":1,"gdbq":2,"solve/_template/rev/vmlift.py --disasm":3,"rat query oracle":4,"rat query pwn":5}
    actions.sort(key=lambda a:(priority.get(a["query"],99),a["target"],a["rule"])); next_actions=[]
    for action in actions:
        old=next((x for x in next_actions if (x["query"],x["target"])==(action["query"],action["target"])),None)
        if old: old["evidence"]=sorted(set(old["evidence"]+action["evidence"]))
        else: next_actions.append(action)
    signals.sort(key=lambda s:(s["kind"],repr(s["value"]),s["quality"])); [v.sort() for v in dimensions.values()]; leads.sort(); unresolved.sort()
    decision=None
    if next_actions:
        chosen=next_actions[0]; decision={"action":chosen["query"],"target":chosen["target"],"evidence":chosen["evidence"],"rule":chosen["rule"]}
    else: unresolved.append("insufficient deterministic evidence to select a bounded first probe")
    return {"schema":"rat.route-result/v2","signals":signals,"dimensions":dimensions,"unresolved":unresolved,"next":next_actions,"capabilities":capabilities,"leads":leads,"decision":decision,"commitment":"provisional" if decision else "unknown","skill":None}
