# Benchmark measurement

`rat-metrics` is an opt-in benchmark harness. Normal solving stays unchanged until a run is started.

## One measured attempt

```bash
rat-metrics begin --root . --run-id babyrev-A0-1 --ablation A0 --challenge-id babyrev --attempt 1 --model gpt-5.6-sol-medium
rat-metrics exec --root . -- revq ./chall --interesting
rat-metrics exec --root . -- decomp ./chall main
# Record model/API usage only when the Codex harness exposes it:
rat-metrics model --root . --input-tokens 12000 --output-tokens 1800 --cache-read-tokens 8000 --context-tokens 24000 --duration-ms 9300
# Record a DEEP escalation only when it actually happens:
rat-metrics deep --root . --reason "FAST route remained ambiguous"
# Record the first confirmed flag/verification event:
rat-metrics verify --root . --flag-found --verified
rat-metrics finish --root . --status completed --outcome verified --flag-found --verified
rat-metrics summary --root . --run-id babyrev-A0-1 --json
```

Run each ablation/challenge combination at least three times.

## Aggregate repeated attempts

After the repetitions, compare variants directly from stored telemetry:

```bash
rat-metrics aggregate --root . --challenge-id babyrev
rat-metrics aggregate --root . --challenge-id babyrev --json
rat-metrics aggregate --root . --challenge-id babyrev --ablation A3
```

The text table reports scored run count, verified solve count/rate, median time-to-flag among verified solves, median peak context, median top-level tool calls/duplicates, and combined structured-cache hit ratio. A `*` marks a group with fewer than the default three scored runs.

Interpretation rules are intentionally conservative:

- **Verified solve rate is the first gate.** Do not prefer a faster variant that materially lowers correctness.
- Time-to-flag/time-to-verified medians are calculated only among verified solves and must be read beside solve rate. This avoids rewarding a variant that solves only an easy subset quickly.
- `infra-failure` and `skipped` runs are reported but excluded from solver success/performance denominators. Timeout/partial/censored solver outcomes remain scored failures.
- Runs marked ineligible at `begin` are excluded by default; use `--include-ineligible` only for diagnostics.
- The currently active telemetry run is excluded from aggregates so an in-progress attempt is never miscounted as a partial failure.
- No significance test or confidence claim is invented from three runs. Three is a minimum smoke comparison, not proof of a small performance difference.

## Recommended A0-A5 mapping

```text
A0 current/main baseline
A1 + FAST front door
A2 + bounded startup instructions / lazy doctrine
A3 + transparent structured query cache
A4 + Function Card v2 + conservative lexical oracle wiring
A5 + experimental bounded backward slice
```

Keep model, reasoning effort, challenge artifact, environment, timeout, and remote conditions fixed inside a comparison. Change one ablation dimension at a time.

## What is counted

`rat-metrics exec` records one **top-level agent tool call**. Internal subprocesses such as `file`, `readelf`, or `strings` launched inside a tool are intentionally not counted as separate agent actions.

Duplicate calls use a normalized command fingerprint. Existing file arguments are resolved to their real path, so `revq chall --interesting` and `revq ./chall --interesting` count as the same call when they refer to the same file.

Structured cache reads/writes performed through `ratlib.contracts` are recorded exactly. The legacy `revq` sidecar cache and Ghidra `decomp` cache are not yet emitted as telemetry events, so the current `cache.hit_ratio` is the **structured-cache ratio**, not a repository-wide cache ratio. The transparent `rat-adapt` path is the migration surface for repeatable expensive queries.

Model token/context numbers are only as complete as the Codex/API usage data supplied through `rat-metrics model`; the tool does not invent unavailable token counts.

## Existing benchmark contract

Each run summary is emitted as `rat.benchmark-result/v1` and preserves CTF-Rat's existing top-level benchmark fields: `benchmark_run_id`, `ablation_id`, `challenge_id`, `attempt`, `status`, `eligible`, `outcome`, timestamps, `metrics`, `oracle`, and `ground_truth`. Telemetry-specific measurements live under `metrics` rather than creating a competing benchmark schema.

`rat-metrics aggregate` is a derived report over those validated per-run results. It does not mutate the run records or introduce a competing source of truth.
