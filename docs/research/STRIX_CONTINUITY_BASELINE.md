# Strix-informed solve-continuity baseline (PR 0)

Status: **SOURCE AUDIT / UNMEASURED**. Tracking: [#133](https://github.com/b0nsu/CTF-Rat/issues/133), under [#132](https://github.com/b0nsu/CTF-Rat/issues/132). This document is a measurement protocol, **not** a benchmark result or a claim that Strix outperforms CTF-Rat.

## Frozen source reference

- CTF-Rat source branch: `dev`, commit `14f1ba121cb4a77f7c048272ad8e50c0faa6b729` (2026-11-07).
- Strix reference: `https://github.com/usestrix/strix`. Its agent/runtime source and test behavior require a separately pinned commit and code-level audit **before** asserting implementation equivalence. Do not compare only README capability claims.
- All benchmark runs must separately record exact working-tree SHA, suite digest, model, effort, runtime/tool/dependency versions, environment and timeout, cache condition, and execution mode.

## Source-first inventory

| Component | Current status | Source-backed observation | Audit question |
| --- | --- | --- | --- |
| Governor | EXISTING | `bin/ratlib/governor.py`: `recommend` prioritizes environment recheck, active direct PASS primitive, refutation, then unresolved discriminator; `check_progress` detects novelty stalls | Do agent actions follow its advice after a verified primitive, or perform avoidable re-triage? |
| Governor regression | EXISTING | `tests/test_governor_continuation.py` covers PASS-vs-unknown order, invalidation, direct/derived quality, consumed primitive | Is the missing behavior in the caller or only in real-workload evidence coverage? |
| Scout result reuse | EXISTING | `bin/ratlib/orchestration.py::reusable_scout_result` matches phase/attempt/lineage/run/checkpoint/contract/inputs/dependencies and validates artifact digests | Which repeated queries are outside exact reuse, and were they necessary new experiments? |
| Durable task controls | EXISTING | `orchestration.py` stores task records and emits STATE events with status/budget/lineage/checkpoint | Are there discarded intermediate artifacts or repeated recovery after task changes? |
| Session metrics | PARTIAL | `bin/ratlib/metrics.py` has envelope-scoped duplicate/cache counters and optional `execve` trace counters | Distinguish measured envelope calls, process calls, and model-side actions; **missing coverage is unknown, not zero** |
| Benchmark suite | EXISTING | `bin/ratlib/bench_suite.py` validates `rat.bench-suite/v2`; `bench/suite.json` defines the corpus | Which entries exercise real post-primitive continuation and external oracle checks? |
| Measured Strix-vs-CTF-Rat improvement | UNKNOWN | No paired runs collected here | Do not state performance wins without matched fixtures and verified oracle outputs |

## A0 reproducible measurement protocol

1. Freeze `dev` SHA, `bench/suite.json` digest, authorized local fixture set, model/effort, timeout, dependencies and tooling. Keep controlled cold/warm cache runs separate.
2. Run existing unit-level invariants first:
   ```sh
   python3 -m unittest tests.test_governor_continuation tests.test_scout_reuse
   python3 bin/ratbench selftest
   ```
3. Run `ratbench eval` in the already-supported real-solve mode, following `bin/ratbench --help` and `bench/README.md` for this pinned version. Preserve full invocation and result/trace artifacts. **Do not substitute router/Mode A score for verified solve rate.**
4. For each solve trace, record: challenge/oracle outcome (external oracle if available), internal completion gate, first valid primitive, first concrete verifier invocation, verified-solve timestamp, model token/context usage, tool calls, duplicate calls, per-scout evidence/artifact digest and process/lineage ID. Report metrics unavailable to the collector as `null`, with measurement coverage.
5. Independently replay `governor.recommend` over recorded STATE prefixes at decision points. Compare suggested vs actual next action; categorize `verification-ready-but-retriaged`, `legitimate-discriminator`, `stale-premise`, `environment-recheck`, `failed-verifier`, and `unknown/uncaptured`. Recommendation agreement by itself is **not** a success metric.
6. Audit cross-task repeated work using the *full* operation fingerprint, exact artifact digest, inputs, tool build/dependency versions, checkpoint and lineage. Count avoidable duplication only after confirming no new evidence, changed environment, or independent measurement requirement.
7. Compare A0 vs any later A1/A2/A3 **one change at a time**, on the identical locked fixture/model/effort/runtime/cache matrix. Report distribution and per-challenge outcomes, not only aggregate mean.

## Required output per run

```json
{
  "source_commit": "14f1ba121cb4a77f7c048272ad8e50c0faa6b729",
  "suite_digest": null,
  "model": null,
  "reasoning_effort": null,
  "environment_digest": null,
  "cache_condition": null,
  "verified_solve": null,
  "challenge_oracle_pass": null,
  "internal_completion_verified": null,
  "false_solved": null,
  "time_to_first_valid_primitive_sec": null,
  "time_from_primitive_to_verifier_sec": null,
  "time_to_verified_solve_sec": null,
  "input_tokens": null,
  "output_tokens": null,
  "peak_context_tokens": null,
  "tool_calls": null,
  "duplicate_tool_calls": null,
  "cache_requests": null,
  "cache_hits": null,
  "subagent_count": null,
  "repeated_scout_queries": null,
  "governor_action_mismatch_count": null,
  "collector_coverage": {}
}
```

Null means **unmeasured**; never treat it as zero, PASS or a successful oracle result. This is a reporting checklist, not a proposed new schema or state store.

## Gate for downstream changes

- **PROCEED #134** only after evidence shows consequential redundant cross-task lookup **not already served** by exact Scout reuse.
- **PROCEED #135** only after proving a real cost from reconstructing solve dependencies; reuse existing task/STATE/compact projections.
- **PROCEED #136** only after showing consequential agent recommendation/action mismatches or post-primitive stalls; retain deterministic validation and do not weaken PASS/SOLVED.
- **REJECT / NO-GAP** when existing runtime already satisfies the requirement or instrumentation is insufficient to identify a cause.
- Always require false SOLVED = 0; cite actual external oracle outcome separately from internal completion.

## Limitations and rollback

No live model solve or matched Strix run has been performed for this source audit. No changes to runtime, STATE, cache, schema, verifier or routing are proposed in PR 0. If later instrumentation is added, keep it read-only and revert independently. Authorized local/fixture targets only.

## PR 0 CI regression evidence (2026-11-14)

- GitHub Actions run: https://github.com/b0nsu/CTF-Rat/actions/runs/43583706811
- Workflow `operational-regression`, job `regression` (job ID `132413635072`): **success**.
- Confirmed successful steps include `python3 bin/rat selftest`, `python3 bin/ratbench selftest`, `python3 bin/ratbench run --corpus synthetic`, `python3 -m unittest discover -s tests -p 'test_*.py'`, `tests/e2e_artifact_handoff.py`, `tests/e2e_analysis.py --category core`, and four `tests/e2e_orchestration.py` scenarios.
- The `analysis-deep` job was **skipped**, not passed.
- These CI steps establish regression compatibility for this documentation-only PR; they **do not** establish real-solve baseline, Strix parity, token improvements, or oracle-verified solves. The `ratbench eval` real-solve experiment is still outstanding.
- Local clone/test attempt was blocked by DNS resolution of `github.com`; GitHub-hosted CI is the available test evidence for this PR.

## Real-corpus feasibility audit (2026-11-14)

The committed `bench/suite.json` already defines **two** `real` entries: `google-ctf-2017-inst-prof` and `google-ctf-2024-notobfuscated`. Both specify `verify.kind=rat-verify-pass` and a claim regex, but **neither** specifies `verify.expected_response_sha256`. Consequently a successful internal completion gate alone cannot establish independent answer-oracle success for either entry; `challenge_oracle_pass` must remain unavailable unless an independent oracle is configured. The presence of the corpus is not itself a measured solve.

The existing `bench/README.md` describes the canonical, answer-free materialization preflight and Mode B CLI. A reproducible operator-side sequence, **not executed in this audit**, is:

```sh
PYTHONPATH=bin python3 -m ratlib.bench_artifacts bench/suite.json --corpus real
python3 bin/ratbench eval --suite bench/suite.json --corpus real \
  --run-id B-real-A0-001 --ablation A0 --model-id '<actual-model>' \
  --reasoning-effort '<actual-effort>' --attempts 3 --timeout 600 \
  --agent '<configured agent CLI with {dir}>'
python3 bin/ratbench report --schema v3
```

**Execution blocker:** this GitHub-connector session has no verified sandboxed agent CLI/model credentials or materialized binary fixture environment, so a real Mode B agent solve cannot be run here. The regression workflow runs Mode A synthetic and tests, not Mode B. Do not invent model, token, cache, time-to-flag, or oracle outcomes. Run the commands only in an authorized isolated operator environment with functional `bwrap` and agent credentials, and preserve result artifacts privately. Do not copy answer material into the agent export.

**Measurement decision:** #133 remains open; do not start #134–#136 runtime behavior changes solely because CI passes. First obtain a Mode B trace and independent oracle coverage (where possible) or explicitly mark the oracle dimension unavailable. This is an environment/measurement gap, not proof of a solver-runtime defect.

**Latest observed PR-head CI (2026-11-14):** `597d928d4ac9616a3b1e54eed2f479a7afbf34a2` passed `operational-regression` run [43588883999](https://github.com/b0nsu/CTF-Rat/actions/runs/43588883999). The `regression` job passed and `analysis-deep` was skipped by its branch/event condition. This is regression evidence, not a real-solve result.
