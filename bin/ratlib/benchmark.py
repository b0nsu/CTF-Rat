"""Deterministic, local-only P4 benchmark contracts and reporting.

The module deliberately does not run challenge solvers.  A runner must write one
immutable result per attempt; this module validates, aggregates, and compares
those records.  Keeping the oracle outside this process prevents an accidental
benchmark oracle/solver information channel.
"""
from __future__ import annotations
import hashlib, json, math, os, random, shlex, statistics, subprocess, uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

class BenchmarkError(ValueError): pass
ROOT = Path(__file__).resolve().parents[2]

def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def digest_file(path): return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()
def digest_tree(path):
    h=hashlib.sha256(); root=Path(path)
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        h.update(str(p.relative_to(root)).encode()+b"\0"); h.update(p.read_bytes())
    return "sha256:"+h.hexdigest()
def load(path):
    raw=Path(path).read_text()
    try: return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml
            return yaml.safe_load(raw)
        except ImportError as e: raise BenchmarkError(f"{path}: use JSON-compatible YAML (PyYAML unavailable)") from e
def dump(path, doc): Path(path).write_text(json.dumps(doc, sort_keys=True, indent=2)+"\n")

REQUIRED_CHALLENGE={"schema","corpus_id","challenge_id","version","license","redistributable","category","secondary_tags","difficulty","architectures","artifacts","scenario","ground_truth","oracle","budgets","seed","split","skip_conditions"}
def validate_challenge(d):
    missing=REQUIRED_CHALLENGE-set(d)
    if missing: raise BenchmarkError("challenge missing fields: "+", ".join(sorted(missing)))
    if d["schema"]!="rat.benchmark-challenge/v1": raise BenchmarkError("invalid challenge schema")
    if d["category"] not in {"pwn-stack-format","pwn-heap-allocator","pwn-advanced","rev-native","rev-vm-obfuscation","rev-platform","regression-tooling"}: raise BenchmarkError("invalid category")
    if d["difficulty"] not in {"easy","medium","hard"}: raise BenchmarkError("invalid difficulty")
    if d["split"] not in {"calibration","holdout"}: raise BenchmarkError("invalid split")
    if not isinstance(d["ground_truth"],dict) or not d["ground_truth"].get("required_claims"): raise BenchmarkError("ground truth required_claims missing")
    if not isinstance(d["oracle"],dict) or not d["oracle"].get("type"): raise BenchmarkError("executable oracle required")
    if d["oracle"].get("network", False): raise BenchmarkError("remote/network oracle forbidden")
    return d

def corpus(root):
    files=sorted(Path(root).glob("*/challenge.yaml"))
    if not files: raise BenchmarkError("corpus contains no challenge.yaml")
    docs=[]
    for p in files:
        d=validate_challenge(load(p)); artifacts=d["artifacts"]
        for key in ("source","oracle"):
            value=artifacts.get(key)
            candidate=(p.parent/value).resolve() if isinstance(value,str) else None
            if not candidate or p.parent.resolve() not in candidate.parents or not candidate.is_file():
                raise BenchmarkError(f"{d['challenge_id']}: missing local {key} fixture")
        if not artifacts.get("build_recipe"): raise BenchmarkError(f"{d['challenge_id']}: build_recipe missing")
        docs.append(d)
    ids=[d["challenge_id"] for d in docs]
    if len(ids)!=len(set(ids)): raise BenchmarkError("duplicate challenge_id")
    return docs
def validate_corpus(root, strict=True):
    docs=corpus(root); report={"challenges":len(docs),"digest":digest_tree(root),"categories":dict(Counter(d["category"] for d in docs)),"difficulty":dict(Counter(d["difficulty"] for d in docs)),"splits":dict(Counter(d["split"] for d in docs))}
    expected={"pwn-stack-format":7,"pwn-heap-allocator":6,"pwn-advanced":5,"rev-native":6,"rev-vm-obfuscation":6,"rev-platform":5,"regression-tooling":5}
    if strict and (len(docs)!=40 or report["categories"]!=expected or report["difficulty"]!={"easy":14,"medium":16,"hard":10} or report["splits"]!={"calibration":24,"holdout":16}): raise BenchmarkError("corpus does not meet the frozen 40-challenge distribution")
    return report

def production_readiness(root):
    """Return release-blocking corpus defects without running a solver.

    ``fixture-smoke`` is deliberately allowed to exercise the collector, but a
    result produced from a known-answer fixture is not an architecture
    measurement.  Keep this check separate from :func:`validate_corpus`: the
    latter validates the versioned fixture contract used by unit tests, while
    this one is required before an external architecture runner may create
    release evidence.
    """
    defects=[]
    for challenge in corpus(root):
        folder=Path(root)/challenge["challenge_id"]
        artifacts=challenge["artifacts"]
        source=folder/artifacts["source"]
        binary=artifacts.get("binary")
        license_=str(challenge.get("license","")).lower()
        tags={str(x).lower() for x in challenge.get("secondary_tags",[])}
        scenario=challenge.get("scenario",{})
        if "synthetic fixture" in license_ or "synthetic" in tags:
            defects.append(f"{challenge['challenge_id']}: synthetic fixture is not release-eligible")
        if challenge.get("redistributable") is not True:
            defects.append(f"{challenge['challenge_id']}: redistribution status is not approved")
        digest=artifacts.get("source_digest")
        if digest != digest_file(source):
            defects.append(f"{challenge['challenge_id']}: source_digest does not bind source artifact")
        if not isinstance(binary,str) or not (folder/binary).is_file():
            defects.append(f"{challenge['challenge_id']}: executable binary artifact is missing")
        elif artifacts.get("binary_digest") != digest_file(folder/binary):
            defects.append(f"{challenge['challenge_id']}: binary_digest does not bind executable artifact")
        if isinstance(scenario.get("smoke_input"),str) and scenario["smoke_input"].startswith("solve:"):
            defects.append(f"{challenge['challenge_id']}: scenario exposes a known solve input")
    return {"release_eligible":not defects,"defects":defects}

def require_production_corpus(root):
    readiness=production_readiness(root)
    if not readiness["release_eligible"]:
        preview="; ".join(readiness["defects"][:3])
        remaining=len(readiness["defects"])-3
        if remaining>0: preview+=f"; ... ({remaining} more)"
        raise BenchmarkError("corpus is not eligible for architecture measurement: "+preview)
    return readiness

def validate_result(d):
    req={"schema","benchmark_run_id","ablation_id","corpus_digest","challenge_id","attempt","status","eligible","outcome","started_at","finished_at","metrics","oracle","ground_truth"}
    missing=req-set(d)
    if missing: raise BenchmarkError("result missing fields: "+", ".join(sorted(missing)))
    if d["schema"]!="rat.benchmark-result/v1" or d["ablation_id"] not in {"A0","A1","A2","A3","A4","A5"}: raise BenchmarkError("invalid benchmark result")
    if d["attempt"] < 1 or d["status"] not in {"completed","timeout","partial","infra-failure","skipped"}: raise BenchmarkError("invalid result status")
    if d["outcome"] not in {"verified","solve-claimed","failed","censored","unknown","skipped"}: raise BenchmarkError("invalid result outcome")
    if d["status"]=="skipped" and d["eligible"]: raise BenchmarkError("skipped result cannot be eligible")
    if d["outcome"]=="skipped" and d["status"]!="skipped": raise BenchmarkError("skipped outcome requires skipped status")
    if d["status"]=="completed" and d["outcome"] in {"censored","unknown","skipped"}: raise BenchmarkError("completed result has non-terminal outcome")
    return d

def read_results(inputs):
    out=[]
    for value in inputs:
        p=Path(value)
        paths=[p] if p.is_file() else sorted(p.rglob("challenge-results.jsonl"))
        if not paths: raise BenchmarkError(f"no challenge-results.jsonl under {p}")
        for f in paths:
            for n,line in enumerate(f.read_text().splitlines(),1):
                if line.strip():
                    try: out.append(validate_result(json.loads(line)))
                    except (json.JSONDecodeError,BenchmarkError) as e: raise BenchmarkError(f"{f}:{n}: {e}")
    return out

def _median(xs): return statistics.median(xs) if xs else None
def _percentile(xs, q):
    if not xs: return None
    xs=sorted(xs); i=(len(xs)-1)*q; lo=int(i); hi=min(lo+1,len(xs)-1)
    return xs[lo]+(xs[hi]-xs[lo])*(i-lo)
def _rate(num,den): return num/den if den else None
def kaplan_meier(rows, field):
    """Return a compact survival curve; censored rows reduce only the risk set."""
    points=[]; grouped=defaultdict(lambda:[0,0])
    for r in rows:
        value=r["metrics"].get(field)
        if not isinstance(value,(int,float)): continue
        grouped[float(value)][0 if r["outcome"]=="verified" else 1]+=1
    at_risk=sum(sum(x) for x in grouped.values()); survival=1.0
    for time_,(events,censored) in sorted(grouped.items()):
        if events and at_risk: survival*=1-events/at_risk
        points.append({"seconds":time_,"survival":survival,"events":events,"censored":censored,"at_risk":at_risk})
        at_risk-=events+censored
    return points
def collect(results):
    # attempt one is the Solve@1 population; retries remain observable but never overwrite it.
    if not results: raise BenchmarkError("cannot collect an empty result set")
    run_ids={r["benchmark_run_id"] for r in results}
    ablations={r["ablation_id"] for r in results}
    if len(run_ids)!=1 or len(ablations)!=1:
        raise BenchmarkError("collect accepts exactly one benchmark run and ablation; collect matrix entries separately")
    keys=[(r["benchmark_run_id"],r["ablation_id"],r["challenge_id"],r["attempt"]) for r in results]
    if len(keys)!=len(set(keys)):
        raise BenchmarkError("duplicate result for benchmark run, ablation, challenge, and attempt")
    first=[r for r in results if r["attempt"]==1]; eligible=[r for r in first if r["eligible"]]
    def values(name): return [r["metrics"][name] for r in first if isinstance(r["metrics"].get(name),(int,float))]
    claims=covered=0; categories=defaultdict(list)
    for r in first:
        categories[r.get("category","unknown")].append(r)
        gt=r["ground_truth"].get("required_claims",[]); claims+=len(gt)
        active=set(r["ground_truth"].get("active_claims",[])); covered+=len(set(gt)&active)
    declared=[r for r in first if r["outcome"] in {"verified","solve-claimed"}]
    false=[r for r in declared if r["outcome"]!="verified" or not r["oracle"].get("passed",False) or not r["oracle"].get("provenance_valid",False)]
    metrics={
      "verified_solve_at_1":_rate(sum(r["outcome"]=="verified" and r["oracle"].get("passed",False) for r in eligible),len(eligible)),
      "median_tts_easy_medium":_median([r["metrics"]["tts_seconds"] for r in eligible if r.get("difficulty") in {"easy","medium"} and isinstance(r["metrics"].get("tts_seconds"),(int,float)) and r["outcome"]=="verified"]),
      "first_primitive_time":_median(values("first_primitive_seconds")), "tokens_per_verified_solve": None,
      "strong_model_token_share":None, "duplicate_call_rate":None,"cache_hit_rate":None,
      "evidence_coverage":_rate(covered,claims), "false_solve_rate":_rate(len(false),len(declared)),
      "top3_recall":_rate(sum(bool(r["metrics"].get("top3_hit")) for r in eligible if r["metrics"].get("top3_hit") is not None),sum(r["metrics"].get("top3_hit") is not None for r in eligible)),
      "exploit_reliability_local":_median(values("exploit_reliability_local")), "exploit_reliability_remote":_median(values("exploit_reliability_remote")), "context_compression_ratio":_median(values("context_compression_ratio")),
      "censored":sum(r["outcome"]=="censored" for r in first), "unknown":sum(r["outcome"]=="unknown" for r in first), "skipped":sum(r["status"]=="skipped" for r in first), "infra_failures":sum(r["status"]=="infra-failure" for r in first)}
    tokens=values("tokens"); solves=sum(r["outcome"]=="verified" for r in eligible); metrics["tokens_per_verified_solve"]=_rate(sum(tokens),solves)
    strong=values("strong_model_tokens"); metrics["strong_model_token_share"]=_rate(sum(strong),sum(tokens)) if strong and tokens else None
    dup=values("duplicate_calls"); inv=values("cacheable_invocations"); metrics["duplicate_call_rate"]=_rate(sum(dup),sum(inv)) if dup and inv else None
    hits=values("cache_hits"); lookups=values("cache_lookups"); metrics["cache_hit_rate"]=_rate(sum(hits),sum(lookups)) if hits and lookups else None
    cat={}
    for name, rs in categories.items():
        es=[r for r in rs if r["eligible"]]; cat[name]={"eligible":len(es),"verified_solve_at_1":_rate(sum(r["outcome"]=="verified" and r["oracle"].get("passed",False) for r in es),len(es)),"top3_recall":_rate(sum(bool(r["metrics"].get("top3_hit")) for r in es if r["metrics"].get("top3_hit") is not None),sum(r["metrics"].get("top3_hit") is not None for r in es))}
    timing={}
    for field in ("tts_seconds","first_primitive_seconds"):
        solved=[r["metrics"][field] for r in eligible if r["outcome"]=="verified" and isinstance(r["metrics"].get(field),(int,float))]
        timing[field]={"median":_median(solved),"p75":_percentile(solved,.75),"p90":_percentile(solved,.90),"kaplan_meier":kaplan_meier(eligible,field)}
    samples={r["challenge_id"]:{"category":r.get("category","unknown"),"verified":r["outcome"]=="verified" and bool(r["oracle"].get("passed")),"evidence_coverage":_rate(len(set(r["ground_truth"].get("required_claims",[]))&set(r["ground_truth"].get("active_claims",[]))),len(r["ground_truth"].get("required_claims",[]))),"metrics":r["metrics"]} for r in first if r["eligible"]}
    corpus_digests={r["corpus_digest"] for r in results}
    if len(corpus_digests)!=1: raise BenchmarkError("collect accepts exactly one corpus digest")
    return {"schema":"rat.benchmark-metrics/v1","metric_version":"v1","benchmark_run_id":next(iter(run_ids)),"ablation_id":next(iter(ablations)),"corpus_digest":next(iter(corpus_digests)),"result_count":len(results),"attempt_one_count":len(first),"eligible_count":len(eligible),"metrics":metrics,"categories":cat,"timing":timing,"samples":samples}

def _metrics_doc(value):
    """Accept a metrics document or the immutable `collect` report that wraps it."""
    if not isinstance(value,dict): raise BenchmarkError("metrics document must be an object")
    if value.get("schema")=="rat.benchmark-metrics/v1": return value
    nested=value.get("metrics")
    if isinstance(nested,dict) and nested.get("schema")=="rat.benchmark-metrics/v1": return nested
    raise BenchmarkError("expected rat.benchmark-metrics/v1 document or collect report")

def threshold_gate(metrics, thresholds, reference=None):
    if thresholds.get("schema")!="rat.benchmark-thresholds/v1": raise BenchmarkError("invalid threshold schema")
    source=thresholds.get("source",{})
    if not isinstance(source,dict) or not source.get("sha256") or not source.get("document"):
        raise BenchmarkError("threshold source locator is required")
    metrics=_metrics_doc(metrics)
    targets=thresholds.get("targets",{}); actual=metrics["metrics"]
    reference_doc=_metrics_doc(reference) if reference is not None else None
    reference_values=reference_doc["metrics"] if reference_doc else {}
    failures=[]; unknown=[]
    mapping={"exploit_reliability":{"local":"exploit_reliability_local","remote":"exploit_reliability_remote"}}
    for key, rule in targets.items():
        if not isinstance(rule,dict) or not rule.get("source"): raise BenchmarkError("threshold source missing for "+key)
        pairs=[]
        if key in mapping: pairs=[(mapping[key][k[:-4]],{"min":v}) for k,v in rule.items() if k.endswith("_min")]
        else: pairs=[(key,rule)]
        for metric, spec in pairs:
            v=actual.get(metric)
            if v is None:
                unknown.append(metric)
                continue
            if "min" in spec and v < spec["min"]: failures.append(f"{metric} {v} < {spec['min']}")
            if "max" in spec and v > spec["max"]: failures.append(f"{metric} {v} > {spec['max']}")
            for direction in ("relative_min", "relative_max"):
                if direction not in spec:
                    continue
                required_baseline=spec.get("baseline","A0")
                if not reference_doc or reference_doc.get("ablation_id")!=required_baseline:
                    unknown.append(metric+":"+direction+":reference-"+str(required_baseline))
                    continue
                baseline=reference_values.get(metric)
                if not isinstance(baseline,(int,float)) or baseline == 0:
                    unknown.append(metric+":"+direction)
                    continue
                change=(v-baseline)/baseline
                if direction == "relative_min" and change < spec[direction]: failures.append(f"{metric} relative change {change} < {spec[direction]}")
                if direction == "relative_max" and change > spec[direction]: failures.append(f"{metric} relative change {change} > {spec[direction]}")
    if actual.get("false_solve_rate") not in (None,0): failures.append("false solve hard gate")
    if unknown: failures.extend("required metric unavailable: "+x for x in unknown)
    return {"passed":not failures,"failures":failures,"unknown":unknown}

def _bootstrap_delta(pairs, seed=0, rounds=1000):
    if not pairs: return None
    rng=random.Random(seed); n=len(pairs); values=[]
    for _ in range(rounds):
        sample=[pairs[rng.randrange(n)] for _ in range(n)]
        values.append(statistics.median(sample))
    return {"median":statistics.median(pairs),"ci95":[_percentile(values,.025),_percentile(values,.975)]}
def _sample_metric(sample, key):
    metrics=sample.get("metrics",{})
    if key=="verified_solve_at_1": return float(bool(sample.get("verified")))
    if key=="median_tts_easy_medium": return metrics.get("tts_seconds")
    if key=="first_primitive_time": return metrics.get("first_primitive_seconds")
    if key=="tokens_per_verified_solve": return metrics.get("tokens") if sample.get("verified") else None
    if key=="duplicate_call_rate":
        return _rate(metrics.get("duplicate_calls"),metrics.get("cacheable_invocations"))
    if key=="cache_hit_rate": return _rate(metrics.get("cache_hits"),metrics.get("cache_lookups"))
    if key=="evidence_coverage": return sample.get("evidence_coverage")
    if key=="top3_recall":
        value=metrics.get("top3_hit"); return float(bool(value)) if value is not None else None
    return None
def compare(candidate, baseline):
    candidate=_metrics_doc(candidate); baseline=_metrics_doc(baseline)
    c=candidate["metrics"]; b=baseline["metrics"]; regressions=[]
    lower={"median_tts_easy_medium","first_primitive_time","tokens_per_verified_solve","duplicate_call_rate"}; higher={"verified_solve_at_1","cache_hit_rate","evidence_coverage","top3_recall"}
    cs=candidate.get("samples",{}); bs=baseline.get("samples",{}); shared=sorted(set(cs)&set(bs)); comparable=bool(shared)
    details={}
    for key in lower|higher:
        if c.get(key) is None or b.get(key) is None: continue
        pairs=[]
        for challenge_id in shared:
            current=_sample_metric(cs[challenge_id],key); previous=_sample_metric(bs[challenge_id],key)
            if isinstance(current,(int,float)) and isinstance(previous,(int,float)): pairs.append(current-previous)
        ci=_bootstrap_delta(pairs); details[key]=ci
        if not ci: continue
        delta=ci["median"]; low_ci,high_ci=ci["ci95"]
        if key in lower and b[key] and delta/b[key] > .10 and low_ci>0: regressions.append(key)
        if key in higher and delta < -.05 and high_ci<0: regressions.append(key)
    for name, v in candidate.get("categories",{}).items():
        old=baseline.get("categories",{}).get(name,{}).get("verified_solve_at_1"); new=v.get("verified_solve_at_1")
        if old is not None and new is not None and new-old <= -.10: regressions.append("category:"+name)
    if not comparable: regressions.append("not-comparable:no-shared-challenges")
    return {"schema":"rat.benchmark-comparison/v1","comparable":comparable,"paired_challenges":len(shared),"passed":not regressions,"regressions":sorted(regressions),"bootstrap":details,"candidate":c,"baseline":b}

def validate_release_metrics(metrics, corpus_root=None, required_ablation="A3"):
    """Fail closed when a release candidate is not one complete, comparable corpus run."""
    metrics=_metrics_doc(metrics)
    root=Path(corpus_root or ROOT/"benchmarks/corpus/v1")
    expected={d["challenge_id"] for d in corpus(root)}
    actual=set(metrics.get("samples",{}))
    if metrics.get("ablation_id")!=required_ablation:
        raise BenchmarkError(f"release candidate must be {required_ablation}, got {metrics.get('ablation_id')}")
    if metrics.get("corpus_digest")!=digest_tree(root):
        raise BenchmarkError("release candidate corpus digest differs from the frozen corpus")
    if metrics.get("attempt_one_count")!=len(expected) or metrics.get("eligible_count")!=len(expected) or actual!=expected:
        missing=sorted(expected-actual); extra=sorted(actual-expected)
        raise BenchmarkError("release candidate is not a complete eligible corpus run"+(f" (missing: {', '.join(missing)})" if missing else "")+(f" (unexpected: {', '.join(extra)})" if extra else ""))
    return metrics

def new_run(corpus_report, ablation, seed, cache):
    return {"schema":"rat.benchmark-run/v1","benchmark_run_id":"bench_"+uuid.uuid4().hex,"created_at":now(),"ablation_id":ablation,"seed":seed,"cache":cache,"corpus_digest":corpus_report["digest"],"status":"created","oracle_visibility":"collector-only"}

def validate_lock(lock, corpus_digest=None, allow_template=False):
    required={"schema","baseline_id","corpus_digest","thresholds","ctf_rat_commit","schema_bundle","toolchain","model_agent","resource_policy","seed_set","status"}
    if lock.get("schema")!="rat.benchmark-baseline-lock/v1" or required-set(lock): raise BenchmarkError("invalid baseline lock")
    if not allow_template and lock["status"]!="approved": raise BenchmarkError("baseline lock is not approved")
    if corpus_digest and lock["corpus_digest"]!=corpus_digest: raise BenchmarkError("corpus digest differs from baseline lock")
    return lock

def validate_transcript(transcript, thresholds):
    if transcript.get("schema")!="rat.benchmark-transcript/v1": raise BenchmarkError("invalid review transcript schema")
    source=thresholds.get("source",{})
    if transcript.get("baseline_id")!=thresholds.get("baseline_id") or transcript.get("source_sha256")!=source.get("sha256"):
        raise BenchmarkError("review transcript does not bind the threshold source")
    reviewers=transcript.get("reviewers",[])
    names=[x.get("reviewer") for x in reviewers if isinstance(x,dict)]
    if transcript.get("status")!="approved" or len(reviewers)!=2 or len(set(names))!=2 or any(not x.get("reviewed_at") or not x.get("attestation") for x in reviewers):
        raise BenchmarkError("two distinct signed reviewer attestations are required")
    return transcript

def release_plan():
    return {"schema":"rat.benchmark-release-plan/v1","cold":[{"ablation":x,"seeds":[1,2,3],"cache":"cold"} for x in ("A0","A1","A2","A3","A4","A5")],"warm":[{"ablation":x,"seeds":[1],"cache":"warm"} for x in ("A1","A2","A3","A4","A5")],"total_runs":23,"promotion_requires":["40-challenge results for every matrix entry","two distinct PDF review attestations","approved baseline lock","PDF and paired regression gates"]}

def fixture_result(run, challenge, root):
    """Run a synthetic local fixture and its checker in isolated child processes.

    The checker consumes only fixture output; no checker source or expected token is
    supplied to an architecture runner.  This smoke backend exists to exercise the
    benchmark plumbing, not to claim a real CTF solve.
    """
    folder=Path(root)/challenge["challenge_id"]; source=folder/challenge["artifacts"]["source"]; oracle=folder/challenge["artifacts"]["oracle"]
    started=now(); scenario=challenge["scenario"]
    try:
        p=subprocess.run([str(source)],input=scenario["smoke_input"],text=True,capture_output=True,timeout=challenge["budgets"]["wall_seconds"],env={"PATH":os.environ.get("PATH","")})
        check=subprocess.run([str(oracle)],input=p.stdout,text=True,capture_output=True,timeout=5,env={"PATH":os.environ.get("PATH","")})
        passed=p.returncode==0 and check.returncode==0
        status="completed"; outcome="verified" if passed else "failed"
    except subprocess.TimeoutExpired:
        p=None; passed=False; status="timeout"; outcome="censored"
    finished=now(); claims=challenge["ground_truth"]["required_claims"]
    return {"schema":"rat.benchmark-result/v1","benchmark_run_id":run["benchmark_run_id"],"ablation_id":run["ablation_id"],"corpus_digest":run["corpus_digest"],"challenge_id":challenge["challenge_id"],"attempt":1,"status":status,"eligible":True,"outcome":outcome,"started_at":started,"finished_at":finished,"category":challenge["category"],"difficulty":challenge["difficulty"],"metrics":{"tts_seconds":0.0,"first_primitive_seconds":0.0,"tokens":0,"strong_model_tokens":0,"duplicate_calls":0,"cacheable_invocations":1,"cache_hits":0,"cache_lookups":1,"top3_hit":True,"exploit_reliability_local":1.0,"exploit_reliability_remote":None,"context_compression_ratio":None},"oracle":{"passed":passed,"provenance_valid":True,"stdout_digest":"sha256:"+hashlib.sha256((p.stdout if p else "").encode()).hexdigest()},"ground_truth":{"required_claims":claims,"active_claims":claims}}

def runner_result(run, challenge, root, command):
    """Adapt an untrusted solver result; only the local oracle can verify it."""
    folder=Path(root)/challenge["challenge_id"]; started=now(); argv=[x.format(challenge=challenge["challenge_id"],ablation=run["ablation_id"],seed=run["seed"],cache=run["cache"]) for x in shlex.split(command)]
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=challenge["budgets"]["wall_seconds"],cwd=folder,env={"PATH":os.environ.get("PATH","")})
        raw=json.loads(p.stdout); candidate=str(raw.get("stdout","")); check=subprocess.run([str(folder/challenge["artifacts"]["oracle"])],input=candidate,text=True,capture_output=True,timeout=5,env={"PATH":os.environ.get("PATH","")})
        passed=p.returncode==0 and check.returncode==0; status="completed"; outcome="verified" if passed else ("solve-claimed" if raw.get("solve_claimed") else "failed")
    except subprocess.TimeoutExpired: raw={}; candidate=""; passed=False; status="timeout"; outcome="censored"
    except (json.JSONDecodeError,OSError): raw={}; candidate=""; passed=False; status="infra-failure"; outcome="unknown"
    metrics=raw.get("metrics",{}) if isinstance(raw.get("metrics",{}),dict) else {}
    metrics={**{"tts_seconds":None,"first_primitive_seconds":None,"tokens":None,"strong_model_tokens":None,"duplicate_calls":None,"cacheable_invocations":None,"cache_hits":None,"cache_lookups":None,"top3_hit":None,"exploit_reliability_local":None,"exploit_reliability_remote":None,"context_compression_ratio":None},**metrics}
    claims=challenge["ground_truth"]["required_claims"]; active=raw.get("active_claims",[]) if isinstance(raw.get("active_claims",[]),list) else []
    return {"schema":"rat.benchmark-result/v1","benchmark_run_id":run["benchmark_run_id"],"ablation_id":run["ablation_id"],"corpus_digest":run["corpus_digest"],"challenge_id":challenge["challenge_id"],"attempt":1,"status":status,"eligible":True,"outcome":outcome,"started_at":started,"finished_at":now(),"category":challenge["category"],"difficulty":challenge["difficulty"],"metrics":metrics,"oracle":{"passed":passed,"provenance_valid":status=="completed","stdout_digest":"sha256:"+hashlib.sha256(candidate.encode()).hexdigest()},"ground_truth":{"required_claims":claims,"active_claims":active}}
