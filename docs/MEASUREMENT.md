# Benchmark measurement

`rat-metrics` is an opt-in benchmark harness. Normal solving stays unchanged until a run is started.

## One measured attempt

```bash
rat-metrics begin --root . --run-id babyrev-A0-1 --ablation A0 --challenge-id babyrev --attempt 1 --model gpt-5.6-sol-medium
rat-metrics exec --root . -- revq ./chall --interesting
rat-metrics exec --root . -- decomp ./chall main
# Record model/API usage when the Codex harness exposes it:
rat-metrics model --root . --input-tokens 12000 --output-tokens 1800 --cache-read-tokens 8000 --context-tokens 24000 --duration-ms 9300
# Record a DEEP escalation only when it actually happens:
rat-metrics deep --root . --reason "FAST route remained ambiguous"
# Record the first confirmed flag/verification event:
rat-metrics verify --root . --flag-found --verified
rat-metrics finish --root . --status completed --outcome verified --flag-found --verified
rat-metrics summary --root . --run-id babyrev-A0-1 --json
```

Run each ablation/challenge combination at least three times. Compare verified solve rate first, then time-to-flag, peak context, duplicate top-level tool calls, tool wall time, token totals, and cache hit ratio.

## What is counted

`rat-metrics exec` records one **top-level agent tool call**. Internal subprocesses such as `file`, `readelf`, or `strings` launched inside a tool are intentionally not counted as separate agent actions.

Duplicate calls use a normalized command fingerprint. Existing file arguments are resolved to their real path, so `revq chall --interesting` and `revq ./chall --interesting` count as the same call when they refer to the same file.

Structured cache reads/writes performed through `ratlib.contracts` are recorded exactly. The legacy `revq` sidecar cache and Ghidra `decomp` cache are not yet emitted as telemetry events, so the current `cache.hit_ratio` is the **structured-cache ratio**, not a repository-wide cache ratio. Cache unification should remove this limitation later.

Model token/context numbers are only as complete as the Codex/API usage data supplied through `rat-metrics model`; the tool does not invent unavailable token counts.

## Existing benchmark contract

The summary is emitted as `rat.benchmark-result/v1` and preserves CTF-Rat's existing top-level benchmark fields: `benchmark_run_id`, `ablation_id`, `challenge_id`, `attempt`, `status`, `eligible`, `outcome`, timestamps, `metrics`, `oracle`, and `ground_truth`. Telemetry-specific measurements live under `metrics` rather than creating a competing benchmark schema.
