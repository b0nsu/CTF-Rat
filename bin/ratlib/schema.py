"""Small, dependency-free validators for the P1 data contracts."""
from __future__ import annotations
import json, re
from datetime import datetime
from typing import Any, Mapping

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID = re.compile(r"(?:[a-z][a-z0-9-]*_[a-z2-7]+|[0-9a-f-]{16,})\Z")
STATES = {"proposed", "supported", "confirmed", "verified", "consumed", "refuted", "invalidated", "stale"}

class ValidationError(ValueError): pass
def _need(doc: Mapping[str, Any], names: tuple[str, ...]):
    missing = [n for n in names if n not in doc]
    if missing: raise ValidationError("missing fields: " + ", ".join(missing))
def _iso(value: Any):
    if not isinstance(value, str): raise ValidationError("timestamp must be a string")
    try: datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise ValidationError("invalid RFC3339 timestamp") from exc
def _digest(value: Any):
    if not isinstance(value, str) or not DIGEST.fullmatch(value): raise ValidationError("invalid sha256 digest")
def _strict(doc: Mapping[str, Any], allowed: set[str]):
    unknown = set(doc) - allowed
    if unknown: raise ValidationError("unknown fields: " + ", ".join(sorted(unknown)))

def validate(doc: Mapping[str, Any], expected: str | None = None) -> Mapping[str, Any]:
    if not isinstance(doc, Mapping): raise ValidationError("document must be an object")
    schema = doc.get("schema")
    if schema == "rat.route-result/v1":
        raise ValidationError("rat.route-result/v1 is obsolete; regenerate with `rat route <bin>`")
    if expected and schema != expected: raise ValidationError("expected %s" % expected)
    if not isinstance(schema, str) or not schema.startswith("rat.") or not schema.rsplit("/v",1)[-1].isdigit():
        raise ValidationError("unsupported schema")
    dispatch = {"rat.tool-result/v1": tool_result, "rat.observation/v1": observation,
      "rat.finding/v1": finding, "rat.checkpoint/v1": checkpoint, "rat.primitive/v1": primitive,
      "rat.run/v1": run, "rat.role-contract/v1": role_contract,
      "rat.task-output/v1": task_output, "rat.skeptic-report/v1": skeptic_report,
      "rat.benchmark-result/v1": benchmark_result, "rat.benchmark-result/v3": benchmark_result_v2,
      "rat.route-result/v2": route_result, "rat.query-result/v1": query_result,
      "rat.cache-stats/v1": cache_stats, "rat.brief-card/v1": brief_card,
      "rat.bench-result/v2": bench_result}
    try: dispatch[schema](doc)
    except KeyError: raise ValidationError("unknown schema %s" % schema)
    return doc
def tool_result(d):
    _need(d,("schema","tool","run_id","invocation_id","status","started_at","finished_at","duration_ms","inputs","parameters","summary","artifacts","findings","diagnostics","exit","provenance")); _strict(d,{"schema","tool","run_id","invocation_id","status","started_at","finished_at","duration_ms","inputs","parameters","summary","artifacts","findings","diagnostics","exit","provenance","extensions","tool_name","params_digest","cache_state"})
    if d["status"] not in {"ok","partial","timeout","error","cancelled"}: raise ValidationError("invalid result status")
    _iso(d["started_at"]); _iso(d["finished_at"])
    if not isinstance(d["duration_ms"],int) or d["duration_ms"] < 0: raise ValidationError("invalid duration")
    if len(json.dumps(d["summary"], ensure_ascii=False).encode()) > 32768: raise ValidationError("summary exceeds 32KiB")
    if not isinstance(d["tool"],Mapping) or set(d["tool"]) != {"name","version","build_digest"}: raise ValidationError("invalid tool")
    _digest(d["tool"]["build_digest"])
    if not isinstance(d["exit"],Mapping) or set(d["exit"]) != {"code","signal","timed_out","cancelled"}: raise ValidationError("invalid exit")
    if not isinstance(d["provenance"],Mapping) or set(d["provenance"]) != {"platform","dependency_versions","policy_digest","cache"}: raise ValidationError("invalid provenance")
    _digest(d["provenance"]["policy_digest"])
    if "tool_name" in d and not isinstance(d["tool_name"],str): raise ValidationError("invalid tool_name")
    if "params_digest" in d and not isinstance(d["params_digest"],str): raise ValidationError("invalid params_digest")
    if "cache_state" in d and d["cache_state"] not in {"hit","miss","bypass"}: raise ValidationError("invalid cache_state")
def observation(d):
    _need(d,("schema","observation_id","run_id","created_at","producer","subject","kind","value","evidence","quality","validity")); _strict(d,{"schema","observation_id","run_id","created_at","producer","subject","kind","value","evidence","quality","validity","extensions"}); _iso(d["created_at"])
    if not d["evidence"]: raise ValidationError("observation requires evidence")
    if d["quality"].get("level") not in {"direct","derived","heuristic"}: raise ValidationError("invalid quality")
    if d["validity"].get("state") not in {"active","invalidated"}: raise ValidationError("invalid validity")
def finding(d):
    _need(d,("schema","finding_id","revision","run_id","created_at","updated_at","title","class","state","confidence","impact","subject","evidence_observation_ids","assumptions","contradictions","related_findings","producer_role","owner_task_id")); _strict(d,{"schema","finding_id","revision","run_id","created_at","updated_at","title","class","state","confidence","impact","subject","evidence_observation_ids","assumptions","contradictions","related_findings","producer_role","owner_task_id","invalidation","extensions"}); _iso(d["created_at"]); _iso(d["updated_at"])
    if d["state"] not in STATES or not 0 <= d["confidence"] <= 1: raise ValidationError("invalid finding state/confidence")
    if d["state"] != "proposed" and not d["evidence_observation_ids"]: raise ValidationError("finding requires evidence")
    if not isinstance(d["revision"], int) or isinstance(d["revision"], bool) or d["revision"] < 1: raise ValidationError("invalid finding revision")
def checkpoint(d):
    _need(d,("schema","checkpoint_id","run_id","created_at","reason","phase","task_id","role","event_cursor","active","invalidation_cursor","context_artifact","budgets","status")); _iso(d["created_at"])
    if d["status"] not in {"open","handoff","converged","cancelled","terminal"}: raise ValidationError("invalid checkpoint status")
def primitive(d):
    _need(d,("schema","primitive_id","name","class","status","input_digest","environment_digest","self_evidence","constraints","side_effects","remote_equivalent","producer","revision")); _strict(d,{"schema","primitive_id","name","class","status","input_digest","environment_digest","self_evidence","constraints","side_effects","remote_equivalent","producer","revision","extensions"})
    if d["status"] not in {"candidate","pass","fail","blocked","stale"}: raise ValidationError("invalid primitive status")
    _digest(d["input_digest"]); _digest(d["environment_digest"])
    if d["status"] == "pass" and len(d["self_evidence"]) < 3: raise ValidationError("PASS requires SELF evidence")
    if not isinstance(d["revision"], int) or isinstance(d["revision"], bool) or d["revision"] < 1: raise ValidationError("invalid primitive revision")
def run(d):
    _need(d,("schema","run_id","created_at","updated_at","challenge","status","inputs","target_policy","environment","toolchain","policy"))
def role_contract(d):
    _need(d,("schema","role","phase","objective","allowed_inputs","required_outputs","forbidden_actions","state_write_scope","capabilities","budgets","stop_conditions"))
    if d["role"] not in {"orchestrator","static-scout","dynamic-scout","hypothesis","primitive-verifier","exploit-builder","skeptic"}: raise ValidationError("invalid role")
    if d["phase"] not in {"solve-P0","solve-P1","solve-P2","solve-P3","solve-P4","solve-P5"}: raise ValidationError("invalid solve phase")
    if set(d["budgets"]) != {"input_tokens","output_tokens","inline_bytes","wall_seconds","tool_calls"} or any(not isinstance(v,int) or v<=0 for v in d["budgets"].values()): raise ValidationError("invalid role budgets")
def task_output(d):
    _need(d,("schema","task_id","status","outputs","evidence_ids")); _strict(d,{"schema","task_id","status","outputs","evidence_ids"})
    if d["status"]!="completed" or not isinstance(d["outputs"],Mapping) or not isinstance(d["evidence_ids"],list): raise ValidationError("invalid task output")
def skeptic_report(d):
    _need(d,("schema","report_id","run_id","task_id","exploit_task_id","verdict","counterexamples","affected_ids","residual_risks")); _strict(d,{"schema","report_id","run_id","task_id","exploit_task_id","verdict","counterexamples","affected_ids","residual_risks"})
    if d["verdict"] not in {"accept","refute","inconclusive"}: raise ValidationError("invalid skeptic verdict")
def benchmark_result(d):
    _need(d,("schema","benchmark_run_id","ablation_id","challenge_id","attempt","status","eligible","outcome","started_at","finished_at","metrics","oracle","ground_truth"))
    if d["ablation_id"] not in {"A0","A1","A2","A3","A4","A5"}: raise ValidationError("invalid ablation")
    if not isinstance(d["attempt"],int) or d["attempt"] < 1: raise ValidationError("invalid attempt")
    if d["status"] not in {"completed","timeout","partial","infra-failure","skipped"}: raise ValidationError("invalid benchmark status")
    if d["outcome"] not in {"verified","solve-claimed","failed","censored","unknown","skipped"}: raise ValidationError("invalid benchmark outcome")
def _benchmark_provenance(d):
    if not isinstance(d,Mapping): raise ValidationError("invalid benchmark provenance")
    _strict(d,{"suite_digest","corpora","agent","execution","environment","toolchain"})
    _need(d,("suite_digest","corpora","agent","execution","environment","toolchain")); _digest(d["suite_digest"])
    corpora=d["corpora"]
    if not isinstance(corpora,list) or not corpora or any(not isinstance(x,str) or x not in {"synthetic","integration","real","private"} for x in corpora) or len(corpora)!=len(set(corpora)): raise ValidationError("invalid benchmark provenance corpora")
    agent=d["agent"]
    if not isinstance(agent,Mapping) or set(agent)!={"executable","command_digest","model_id","reasoning_effort"}: raise ValidationError("invalid benchmark provenance agent")
    if not isinstance(agent["executable"],str) or not agent["executable"]: raise ValidationError("invalid benchmark agent executable")
    _digest(agent["command_digest"])
    for key in ("model_id","reasoning_effort"):
        if agent[key] is not None and (not isinstance(agent[key],str) or not agent[key]): raise ValidationError("invalid benchmark agent %s" % key)
    execution=d["execution"]
    if not isinstance(execution,Mapping) or set(execution)!={"timeout_seconds","observer_execve_trace"}: raise ValidationError("invalid benchmark provenance execution")
    if not isinstance(execution["timeout_seconds"],int) or isinstance(execution["timeout_seconds"],bool) or execution["timeout_seconds"] < 1: raise ValidationError("invalid benchmark timeout")
    if not isinstance(execution["observer_execve_trace"],bool): raise ValidationError("invalid benchmark observer flag")
    environment=d["environment"]
    if not isinstance(environment,Mapping) or set(environment)!={"os","arch","runtime"} or any(not isinstance(environment[k],str) or not environment[k] for k in environment): raise ValidationError("invalid benchmark environment")
    toolchain=d["toolchain"]
    if not isinstance(toolchain,Mapping) or set(toolchain)!={"ctf_rat_revision","schema_bundle"} or any(not isinstance(toolchain[k],str) or not toolchain[k] for k in toolchain): raise ValidationError("invalid benchmark toolchain")
def _benchmark_routing(d):
    """Validate optional observer-owned route/commitment telemetry.

    The projection is optional when an attempt never invoked the routing front door.
    Live Mode B producers populate it from the canonical STATE route-assessment
    notes; no route is inferred retroactively from the current router.
    """
    fields={"first_dimensions","first_action","first_commitment","route_assessment_count","decision_revision_count","first_skill"}
    if not isinstance(d,Mapping) or set(d)!=fields: raise ValidationError("invalid benchmark routing fields")
    if d["first_dimensions"] is not None and not isinstance(d["first_dimensions"],Mapping): raise ValidationError("invalid benchmark first_dimensions")
    if d["first_action"] is not None and not isinstance(d["first_action"],Mapping): raise ValidationError("invalid benchmark first_action")
    if d["first_commitment"] not in {None,"committed","provisional","unknown"}: raise ValidationError("invalid benchmark first_commitment")
    for key in ("route_assessment_count","decision_revision_count"):
        value=d[key]
        if not isinstance(value,int) or isinstance(value,bool) or value < 0: raise ValidationError("invalid benchmark %s" % key)
    if d["decision_revision_count"] > max(0,d["route_assessment_count"]-1): raise ValidationError("decision revisions exceed assessments")
    if d["first_skill"] is not None and (not isinstance(d["first_skill"],str) or not d["first_skill"]): raise ValidationError("invalid benchmark first_skill")
    if d["route_assessment_count"] == 0:
        if any(d[key] is not None for key in ("first_dimensions","first_action","first_commitment","first_skill")): raise ValidationError("empty routing assessment cannot report first fields")
    elif d["first_dimensions"] is None or d["first_commitment"] is None: raise ValidationError("routing assessment requires first fields")
def _benchmark_observations(d):
    """Validate optional envelope-scoped counters without implying run-wide coverage."""
    if not isinstance(d, Mapping) or set(d) != {"tool_result_envelopes"}:
        raise ValidationError("invalid benchmark observations")
    row = d["tool_result_envelopes"]
    fields = {"scope", "envelope_count", "cache_requests", "cache_hits",
              "cache_unusable_hits", "cache_hit_ratio", "captured_stdout_stderr_bytes"}
    if not isinstance(row, Mapping) or set(row) != fields:
        raise ValidationError("invalid benchmark envelope observation fields")
    if row["scope"] != "tool-result-envelopes-only":
        raise ValidationError("invalid benchmark observation scope")
    for key in ("envelope_count", "cache_requests", "cache_hits", "cache_unusable_hits"):
        n = row[key]
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            raise ValidationError("invalid benchmark observation %s" % key)
    total, requests, hits, unusable = (
        row["envelope_count"], row["cache_requests"],
        row["cache_hits"], row["cache_unusable_hits"])
    if total == 0 or requests > total or hits + unusable > requests:
        raise ValidationError("incoherent benchmark envelope counts")
    ratio = row["cache_hit_ratio"]
    if requests == 0:
        if ratio is not None:
            raise ValidationError("zero cache requests cannot have a hit ratio")
    elif isinstance(ratio, bool) or not isinstance(ratio, (int, float)) or abs(ratio - hits / requests) > 1e-9:
        raise ValidationError("incoherent benchmark envelope hit ratio")
    size = row["captured_stdout_stderr_bytes"]
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise ValidationError("invalid benchmark envelope output size")

def benchmark_result_v2(d):
    _need(d,("schema","benchmark_run_id","ablation_id","challenge_id","attempt","status","eligible","outcome","started_at","finished_at","metrics","oracle","ground_truth"))
    _strict(d,{"schema","benchmark_run_id","ablation_id","challenge_id","attempt","status","eligible","outcome","started_at","finished_at","metrics","oracle","ground_truth","provenance","routing","observations"})
    if d["ablation_id"] not in {"A0","A1","A2","A3","A4","A5"}: raise ValidationError("invalid ablation")
    if not isinstance(d["attempt"],int) or d["attempt"] < 1: raise ValidationError("invalid attempt")
    if d["status"] not in {"completed","timeout","partial","infra-failure","skipped"}: raise ValidationError("invalid benchmark status")
    if d["outcome"] not in {"verified","solve-claimed","failed","censored","unknown","skipped"}: raise ValidationError("invalid benchmark outcome")
    _iso(d["started_at"]); _iso(d["finished_at"])
    if "provenance" in d: _benchmark_provenance(d["provenance"])
    if "routing" in d: _benchmark_routing(d["routing"])
    if "observations" in d: _benchmark_observations(d["observations"])
    groups = {
        "correctness": {"verified_solve","false_solved","oracle_pass"},
        "latency": {"time_to_first_query_ms","time_to_first_hypothesis_ms","time_to_first_valid_primitive_ms","time_to_verified_solve_ms"},
        "context": {"input_tokens","output_tokens","peak_context_tokens","tool_output_bytes"},
        "tools": {"tool_calls","duplicate_tool_calls","ghidra_runs","cfgfast_runs","symbolic_runs","subagent_count"},
        "cache": {"cache_requests","cache_hits","cache_hit_ratio","bytes_reused","cold_warm"},
        "reasoning": {"hypotheses_created","hypotheses_refuted","pivot_count","deep_escalations"},
        "artifacts": {"functions_decompiled","raw_output_size","compressed_output_size","artifact_count"},
    }
    metrics = d["metrics"]
    if not isinstance(metrics,Mapping) or set(metrics) != set(groups): raise ValidationError("benchmark metrics missing required groups")
    for name, fields in groups.items():
        group = metrics[name]
        if not isinstance(group,Mapping) or set(group) != fields: raise ValidationError("invalid metrics.%s fields" % name)
    if metrics["cache"]["cold_warm"] not in {"cold","warm"}: raise ValidationError("invalid metrics.cache.cold_warm")
    ratio = metrics["cache"]["cache_hit_ratio"]
    if ratio is not None and not (isinstance(ratio,(int,float)) and 0 <= ratio <= 1): raise ValidationError("invalid metrics.cache.cache_hit_ratio")

def route_result(d):
    _need(d,("schema","signals","dimensions","unresolved","next","capabilities","leads","decision","commitment","skill"))
    forbidden={"track","subroute","confidence","alternatives","score_semantics","conflict"}&set(d)
    if forbidden: raise ValidationError("obsolete route v1 fields: %s; regenerate with `rat route <bin>`" % ", ".join(sorted(forbidden)))
    if not isinstance(d["signals"],list) or any(
        not isinstance(s,Mapping) or {"kind","value","quality"} - set(s) or s["quality"] not in {"fact","heuristic"}
        for s in d["signals"]): raise ValidationError("invalid signals")
    if not isinstance(d["capabilities"],Mapping) or not all(isinstance(v,bool) for v in d["capabilities"].values()):
        raise ValidationError("invalid capabilities")
    if d["skill"] is not None and not isinstance(d["skill"],str): raise ValidationError("invalid skill")
    if not isinstance(d["next"],list) or any(
        not isinstance(n,Mapping) or {"query","target"} - set(n) for n in d["next"]): raise ValidationError("invalid next")
    if (not isinstance(d["leads"],list) or any(not isinstance(x,str) or not x for x in d["leads"])
        or len(set(d["leads"])) != len(d["leads"])):
        raise ValidationError("invalid non-exclusive route leads")
    if d["commitment"] not in {"committed","provisional","unknown"}: raise ValidationError("invalid route commitment")
    if d["commitment"] != "committed" and d["skill"] is not None: raise ValidationError("non-committed route cannot lock a skill")
    dims=d["dimensions"]; fields={"vulnerability_surfaces","program_shapes","obstacles","constraints"}
    if not isinstance(dims,Mapping) or set(dims)!=fields: raise ValidationError("invalid route dimensions")
    if any(not isinstance(dims[n],list) or any(not isinstance(v,str) for v in dims[n]) for n in fields): raise ValidationError("invalid route dimension values")
    if not isinstance(d["unresolved"],list) or any(not isinstance(v,str) for v in d["unresolved"]):
        raise ValidationError("invalid route unresolved")
    for action in d["next"]:
        if not isinstance(action,Mapping) or {"query","target","evidence","rule"}-set(action): raise ValidationError("invalid route action")
    decision=d["decision"]
    if decision is not None and (not isinstance(decision,Mapping) or {"action","target","evidence","rule"}-set(decision)): raise ValidationError("invalid route decision")
    if decision is None and d["commitment"]!="unknown": raise ValidationError("missing decision requires unknown commitment")

_QUERY_DIAGNOSTIC_CODES = {"input_invalid","dependency_missing","timeout","partial","stale_cache","ambiguous","verification_fail"}
def query_result(d):
    _need(d,("schema","query","status","facts","heuristics","artifacts","coverage","diagnostics","provenance"))
    if d["status"] not in {"ok","partial","error"}: raise ValidationError("invalid query status")
    if not isinstance(d["coverage"],Mapping) or {"complete","scope","omitted"} - set(d["coverage"]):
        raise ValidationError("invalid coverage")
    complete = d["coverage"]["complete"]
    if not isinstance(complete,bool): raise ValidationError("coverage.complete must be boolean")
    if complete and d["status"] != "ok": raise ValidationError("complete coverage requires ok query status")
    if not isinstance(d["diagnostics"],list) or any(not isinstance(x,Mapping) or "code" not in x for x in d["diagnostics"]):
        raise ValidationError("invalid diagnostics")
    if any(x["code"] not in _QUERY_DIAGNOSTIC_CODES for x in d["diagnostics"]): raise ValidationError("unknown diagnostic code")
    if not isinstance(d["provenance"],Mapping) or "cache" not in d["provenance"]: raise ValidationError("invalid provenance")
    if not isinstance(d["artifacts"],list): raise ValidationError("invalid artifacts")
    if not isinstance(d["facts"],Mapping): raise ValidationError("invalid facts")
    if not isinstance(d["heuristics"],Mapping): raise ValidationError("invalid heuristics")

def brief_card(d):
    _need(d,("schema","binary","capabilities","route","track_summary","libc","truncated","side_effects"))
    if not isinstance(d["capabilities"],Mapping): raise ValidationError("invalid capabilities")
    if not isinstance(d["route"],Mapping): raise ValidationError("invalid route")
    if not isinstance(d["track_summary"],Mapping): raise ValidationError("invalid track_summary")
    if not isinstance(d["libc"],Mapping): raise ValidationError("invalid libc")
    if not isinstance(d["truncated"],list): raise ValidationError("invalid truncated")
    if not isinstance(d["side_effects"],list): raise ValidationError("invalid side_effects")

_BENCH_OUTCOMES = {"route-miss","solved","route-ok-verify-skipped","verify-fail","solve-claimed","fail"}
def bench_result(d):
    _need(d,("schema","mode","run_id","id","outcome","wall_ms"))
    if d["mode"] not in {"A","B"}: raise ValidationError("invalid bench mode")
    if d["outcome"] not in _BENCH_OUTCOMES: raise ValidationError("invalid bench outcome")
    if not isinstance(d["wall_ms"],int) or d["wall_ms"] < 0: raise ValidationError("invalid wall_ms")

def cache_stats(d):
    _need(d,("schema","store","total_entries","by_backend","oldest_produced_at","newest_produced_at"))
    _strict(d,{"schema","store","total_entries","by_backend","oldest_produced_at","newest_produced_at"})
    if not isinstance(d["total_entries"],int) or d["total_entries"] < 0: raise ValidationError("invalid total_entries")
    if not isinstance(d["by_backend"],Mapping): raise ValidationError("invalid by_backend")
