"""Deterministic Router v2: project evidence, expose candidate probes, recommend only on dominance."""
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
QUALITY_RANK={"unknown":0,"heuristic":1,"fact":2}
COST_RANK={"high":0,"medium":1,"low":2}
SPECIFICITY_RANK={"general":0,"bounded":1,"concrete":2}

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
def _action(query,target,evidence,rule,*,resolves,expected_evidence,cost="low",specificity="bounded",blocking=False):
    return {"query":query,"target":target,"evidence":sorted(set(evidence)),"rule":rule,
            "resolves":sorted(set(resolves)),"expected_evidence":expected_evidence,
            "cost":cost,"specificity":specificity,"blocking":bool(blocking)}

def _evidence_quality(action,signal_quality):
    ranks=[QUALITY_RANK.get(signal_quality.get(kind,"unknown"),0) for kind in action["evidence"]]
    rank=max(ranks) if ranks else 0
    return next(name for name,value in QUALITY_RANK.items() if value==rank)

def _dominates(left,right):
    """Pareto dominance over semantic probe properties, never tool-category priority.

    Specificity only breaks ties between heuristic/unknown probes. Once both
    candidates have fact-quality support, a concrete target must not erase an
    independent fact-backed lead merely because it is more specific.
    """
    lq,rq=QUALITY_RANK[left["evidence_quality"]],QUALITY_RANK[right["evidence_quality"]]
    left_base=(1 if left["blocking"] else 0,lq,COST_RANK[left["cost"]])
    right_base=(1 if right["blocking"] else 0,rq,COST_RANK[right["cost"]])
    if any(a<b for a,b in zip(left_base,right_base)):
        return False
    strictly_better=any(a>b for a,b in zip(left_base,right_base))
    if lq<=1 and rq<=1:
        ls,rs=SPECIFICITY_RANK[left["specificity"]],SPECIFICITY_RANK[right["specificity"]]
        if ls<rs:
            return False
        strictly_better = strictly_better or ls>rs
    return strictly_better

def _recommend(actions):
    if not actions:
        return None
    if len(actions)==1:
        return actions[0]
    maximal=[a for a in actions if not any(_dominates(other,a) for other in actions if other is not a)]
    if len(maximal)==1:
        return maximal[0]
    queries={a["query"] for a in maximal}
    if len(queries)==1:
        return {"query":next(iter(queries)),"target":None,
                "evidence":sorted({e for a in maximal for e in a["evidence"]}),
                "rule":"co-equal candidate probes share one bounded front door; choose one candidate from next",
                "resolves":sorted({r for a in maximal for r in a["resolves"]}),
                "expected_evidence":"candidate-dependent","cost":"low",
                "specificity":"general","blocking":any(a["blocking"] for a in maximal),
                "evidence_quality":max((a["evidence_quality"] for a in maximal),
                                       key=lambda q:QUALITY_RANK[q])}
    return None

def route(*,profile=None,revq=None,interesting=None):
    """Project observations into candidate probes; never choose a challenge class."""
    imports=set((profile or {}).get("imports",[]) or [])|set((revq or {}).get("imports",[]) or [])
    dimensions={name:[] for name in DIMS}; signals=[]; unresolved=[]; leads=[]; actions=[]
    capabilities={"profile":profile is not None,"revq":revq is not None}; is_pe=(revq or {}).get("platform")=="pe"
    if is_pe:
        _sig(signals,"pe-platform","PE/Windows","fact"); _add(dimensions["constraints"],"pe-windows")
        actions.append(_action("solve/_template/rev/qiling_trace.py","pe-dynamic-emulation-rootfs-required",["pe-platform"],
                               "PE execution requires the bounded Windows emulation path",
                               resolves=["whether the artifact can execute through the bounded PE emulation path"],
                               expected_evidence="runtime-direct",cost="medium",blocking=True))
    typed=(revq or {}).get("evasion_signals",[]) if (revq or {}).get("evasion_signal_schema")==EVASION_SIGNAL_SCHEMA else []
    packing=next((s for s in typed if isinstance(s,dict) and s.get("kind")=="packer-section" and s.get("quality")=="fact"),None)
    packing=packing or next((s for s in typed if isinstance(s,dict) and s.get("kind")=="high-entropy" and s.get("quality")=="heuristic"),None)
    if packing:
        _sig(signals,packing["kind"],packing.get("value"),packing["quality"]); _add(dimensions["obstacles"],"packing"); _add(leads,"packing")
        _add(unresolved,"packing is an analysis obstacle; the underlying program shape remains open")
        actions.append(_action("gdbq","verify-packer-and-unpack-need-before-dynamic-tracing",[packing["kind"]],
                               "typed packing evidence requires confirmation",
                               resolves=["whether packing is active and unpacking is required before deeper analysis"],
                               expected_evidence="runtime-direct",blocking=True))
    hits=sorted(imports&KERNEL)
    if hits and not is_pe:
        _sig(signals,"kernel-imports",hits,"fact"); _add(dimensions["program_shapes"],"kernel-candidate"); _add(leads,"kernel")
        _add(unresolved,"kernel imports do not prove a kernel artifact or target environment")
        actions.append(_action("rat query pwn","confirm-kernel-artifact-and-environment-before-kernel-tooling",["kernel-imports"],
                               "kernel tooling requires environment confirmation",
                               resolves=["whether the artifact and environment are actually a kernel target"],
                               expected_evidence="structured-static",blocking=True))
    hits=sorted(imports&HEAP)
    if hits:
        _sig(signals,"heap-imports",hits,"fact"); _add(dimensions["vulnerability_surfaces"],"heap-lifetime-candidate"); _add(leads,"heap-lifetime")
        _add(unresolved,"allocator imports do not prove attacker-controlled lifetime, reuse, or overlap")
        if not is_pe:
            actions.append(_action("rat query pwn","inspect-bounded-allocator-callsites-and-lifetimes",["heap-imports"],
                                   "allocator use calls for bounded lifetime inspection",
                                   resolves=["whether allocator lifetime, reuse, or overlap is attacker-controlled"],
                                   expected_evidence="structured-static"))
    fh,ih=sorted(imports&FORMAT),sorted(imports&INPUT)
    if fh and ih:
        _sig(signals,"format-input-imports",sorted(set(fh+ih)),"fact"); _add(dimensions["vulnerability_surfaces"],"format-string-candidate"); _add(leads,"format-string")
        _add(unresolved,"prove attacker control reaches a format argument")
        if not is_pe:
            actions.append(_action("rat query pwn","inspect-bounded-format-callsites-before-runtime-probe",["format-input-imports"],
                                   "format and input imports justify callsite inspection",
                                   resolves=["whether attacker-controlled data reaches a format argument"],
                                   expected_evidence="structured-static"))
    hits=sorted(imports&OVERFLOW)
    if hits:
        _sig(signals,"overflow-imports",hits,"fact" if imports&STRONG else "heuristic"); _add(dimensions["vulnerability_surfaces"],"stack-overwrite-candidate"); _add(leads,"stack-overwrite")
        _add(unresolved,"prove a concrete overwrite or PC-control primitive; import presence is insufficient")
        if _fact(profile,"elf.nx") is True: _sig(signals,"elf-nx",True,"fact"); _add(dimensions["constraints"],"nx")
        if not is_pe:
            actions.append(_action("rat query pwn","inspect-bounded-input-callsite-then-measure-overwrite",["overflow-imports"],
                                   "an input sink requires callsite inspection before a crash probe",
                                   resolves=["whether input reaches an overwrite-capable callsite before measuring PC control"],
                                   expected_evidence="structured-static"))
    checker=[]; checker_evidence={}
    for item in interesting or []:
        if not isinstance(item,dict) or not _func(revq,item.get("func")): continue
        name=item["func"]; compares=sorted(_calls(revq,name)&COMPARE); oracle=_oracle(revq,name)
        if compares or oracle:
            checker.append(name); ev=["checker-function"]; _sig(signals,"checker-function",{"func":name},"heuristic")
            if compares: _sig(signals,"compare-calls",{"func":name,"calls":compares},"fact"); ev.append("compare-calls")
            if oracle: _sig(signals,"checker-oracle-strings",{"func":name,**oracle},"heuristic"); ev.append("checker-oracle-strings")
            checker_evidence[name]=ev
    if checker:
        _add(dimensions["program_shapes"],"checker"); _add(leads,"checker"); _add(unresolved,"checker semantics and success/failure oracle remain unverified")
        target=sorted(set(checker))[0]; actions.append(_action("rat query func",target,checker_evidence[target],
                               "structured checker evidence supplies a concrete function target",
                               resolves=["checker semantics and success/failure branch structure"],
                               expected_evidence="structured-static",specificity="concrete"))
    names=" ".join(f.get("name","") for f in (revq or {}).get("functions",[]) or [] if isinstance(f,dict)).lower(); blob=_blob(revq)
    vh=sorted({h for h in VM if h in names or h in blob})
    if vh:
        _sig(signals,"vm-dispatch-hint",vh,"heuristic"); _add(dimensions["program_shapes"],"vm-candidate"); _add(leads,"vm"); _add(unresolved,"VM hints do not prove a dispatch loop or bytecode semantics")
        actions.append(_action("solve/_template/rev/vmlift.py --disasm","prove-dispatch-loop-before-vm-lift",["vm-dispatch-hint"],
                               "VM hints require dispatch-loop confirmation",
                               resolves=["whether a dispatch loop and bytecode semantics exist"],
                               expected_evidence="structured-static",cost="medium"))
    ch=sorted({h for h in CRYPTO if h in blob})
    if ch or (interesting and not checker):
        if ch: _sig(signals,"crypto-hint",ch,"heuristic")
        _add(dimensions["program_shapes"],"oracle-needed"); _add(leads,"oracle-discovery"); _add(unresolved,"a success/failure oracle must be bounded before symbolic execution")
        actions.append(_action("rat query oracle","success-failure-oracle-before-symbolic",["crypto-hint"] if ch else [],
                               "interesting code requires an oracle before symbolic execution",
                               resolves=["where the bounded success/failure oracle is"],
                               expected_evidence="structured-static"))
    actions.sort(key=lambda a:(a["query"],a["target"],a["rule"])); next_actions=[]
    for action in actions:
        old=next((x for x in next_actions if (x["query"],x["target"])==(action["query"],action["target"])),None)
        if old:
            old["evidence"]=sorted(set(old["evidence"]+action["evidence"]))
            old["resolves"]=sorted(set(old["resolves"]+action["resolves"]))
            old["blocking"]=old["blocking"] or action["blocking"]
        else:
            next_actions.append(action)
    signal_quality={}
    for signal in signals:
        kind=signal["kind"]; quality=signal["quality"]
        if QUALITY_RANK.get(quality,0)>QUALITY_RANK.get(signal_quality.get(kind,"unknown"),0):
            signal_quality[kind]=quality
    for action in next_actions:
        action["evidence_quality"]=_evidence_quality(action,signal_quality)
    signals.sort(key=lambda s:(s["kind"],repr(s["value"]),s["quality"])); [v.sort() for v in dimensions.values()]; leads.sort(); unresolved.sort()
    chosen=_recommend(next_actions); decision=None
    if chosen:
        decision={"action":chosen["query"],"target":chosen["target"],"evidence":chosen["evidence"],
                  "rule":chosen["rule"],"resolves":chosen["resolves"],
                  "expected_evidence":chosen["expected_evidence"],"cost":chosen["cost"],
                  "specificity":chosen["specificity"],"blocking":chosen["blocking"],
                  "evidence_quality":chosen["evidence_quality"]}
    elif not next_actions:
        unresolved.append("insufficient deterministic evidence to select a bounded first probe")
    return {"schema":"rat.route-result/v2","signals":signals,"dimensions":dimensions,"unresolved":unresolved,
            "next":next_actions,"capabilities":capabilities,"leads":leads,"decision":decision,
            "commitment":"provisional" if next_actions else "unknown","skill":None}
