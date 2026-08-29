# Desktop v0.3 release gate

This document is the release decision checklist for the CTF-Rat Desktop v0.3 preview.

It does **not** define a new telemetry store or benchmark format. Repository artifacts, `ratbench`, canonical STATE v2, session metrics, and CI artifacts remain the evidence sources. Desktop remains an observer/controller over the canonical runtime.

## Release decision

Promote package metadata to `0.3.0`, mark PR #13 ready, or merge only after all correctness gates pass and real-session measurements have been reconciled against a comparable baseline.

Synthetic CI is necessary but is not sufficient.

## Comparison identity

A comparison is valid only when the following are recorded and materially equivalent between baseline and Desktop-enabled runs:

- challenge/corpus identity
- challenge artifact digest
- CTF-Rat revision
- model and reasoning-effort label, when an LLM is involved
- agent command identity
- timeout
- environment identity
- tool/schema versions available from existing provenance
- Desktop ON/OFF condition

Use the existing benchmark/run provenance mechanisms where available. Do not invent a Desktop-specific provenance database.

## Required session measurements

Collect, when observable:

### Correctness

- `verified_solve`
- false `VERIFIED` count
- missed STATE event count
- unexpected stream reset / cursor anomaly count
- Desktop-caused solver/runtime failure count

### Time

- `time_to_first_hypothesis`
- `time_to_first_valid_primitive`
- `time_to_verified_solve`
- `time_to_flag`
- total session wall time

### Context / orchestration

- input tokens
- output tokens
- peak context tokens
- hypothesis count
- pivot count
- subagent count / subagent token share, when observable

### Tools / cache / analysis

- tool calls
- duplicate tool calls
- cache requests
- cache hits
- cache hit ratio
- functions decompiled
- FAST count and duration
- DEEP count and duration
- FUNC count and duration
- ORACLE count and duration
- SLICE count and duration

### Desktop/runtime overhead

- STATE event count and JSONL bytes
- artifact count and bytes
- `/api/live` p50 / p95 / max latency
- artifact refresh p50 / p95 / max latency
- `ratd` CPU usage
- `ratd` peak RSS
- terminal retained-log growth

Unavailable metrics remain unavailable/null. Do not rewrite missing observations as zero.

## Hard correctness gates

The release is blocked when any of the following is observed and not explained by an invalid test setup:

- false `VERIFIED` > 0
- missed STATE events > 0
- unexplained cursor/history mixing or reset anomaly > 0
- Desktop causes a solver/runtime failure that does not occur under the comparable baseline
- Desktop presents a finding, primitive, verification, evidence relation, or completion state inconsistent with canonical STATE/completion data
- analysis controls execute a target, argv, slice depth/source, or verifier path outside their committed bounded contracts

FAST is never allowed to weaken verification.

## Performance decision rule

Do not use an arbitrary global percentage as a release claim.

For each comparable challenge/run pair:

1. compare Verified Solve Rate first;
2. compare Time-to-Flag / Time-to-Verified-Solve when solved;
3. attribute regressions using tool-call, duplicate-call, cache, decompile, context, and Desktop-overhead measurements;
4. reject a Desktop optimization if it makes the measured target path worse without a compensating correctness or reproducibility gain;
5. investigate material regressions before release rather than averaging them away across unrelated challenges.

Synthetic polling/artifact benchmarks remain regression baselines for the Desktop transport/projection layer, not evidence that solving performance improved.

## Required evidence bundle

Before release, retain or link:

- baseline run records
- Desktop-enabled run records
- exact comparison/provenance identity
- final Desktop polling benchmark artifact
- final Desktop artifact benchmark artifact
- final Linux `.deb` / AppImage CI artifact
- final `desktop-workbench` workflow result
- final `operational-regression` result
- any relevant failure/reproduction log

## Current synthetic baseline

At Desktop head `ccc3537932097e15b4a7e6574b9fbbed085d1666`, workflow run `33237906876` is green.

5,000-event synthetic polling baseline on that runner:

- unchanged `/api/live` wall p50: `0.008 ms`
- combined changed refresh wall p50: `23.451 ms`
- legacy changed refresh wall p50: `45.169 ms`
- changed refresh ratio: `1.93x`
- telemetry projection wall p50: `71.743 ms`

500 artifacts × 64 KiB on that runner:

- full listing wall p50: `13.878 ms`
- unchanged inventory wall p50: `2.634 ms`
- inventory ratio: `5.27x`
- one verified preview wall p50: `0.163 ms`

These are current-run baselines only. They are not causal claims against results measured on different runners or revisions.

Current CI artifacts:

- benchmark artifact id `9710464834`, digest `sha256:d3ca290a6a3ad9500bb3b38a1a3c3b3dbc57ebaa77a4823cf97193f34f5a70ec`
- Linux bundle artifact id `9710524764`, digest `sha256:e384fb34d9f0c05c0878eaa6fb10c2663f88a2b4226c7921ba099e4fb6e3f8c2`

## Release checklist

- [ ] real-session baseline and Desktop-enabled samples are comparable
- [ ] hard correctness gates pass
- [ ] Verified Solve Rate is reconciled
- [ ] Time-to-Flag / Time-to-Verified-Solve regressions are explained
- [ ] tool/cache/context regressions are explained
- [ ] Desktop CPU/RSS/transport overhead is measured
- [ ] final branch is still based on the intended `dev` head
- [ ] final Desktop CI passes
- [ ] final operational regression passes
- [ ] package version is changed to `0.3.0` only after the evidence above is accepted
- [ ] PR is marked ready only after the same evidence is recorded

## Explicitly deferred

The following are not release blockers for the current preview unless the canonical runtime first exposes the required contract:

- Desktop-defined high-level typed solver-intent subsystem
- Desktop-defined verifier execution workflow
- new state/cache/telemetry databases
- SSE/WebSocket replacement for polling without real-session evidence that polling is a material bottleneck

One concept should continue to have one canonical runtime implementation with Desktop acting as a bounded adapter/projection.