# Evidence-backed continuation: implementation and ablation

## Scope and baseline

- Base: `main` at `517964d3c379c53754123ea6da2d87714342ee4e`.
- A0: the unmodified base commit. A1: this branch (Governor advice ordering,
  regression tests, and matching agent instruction).
- No new router, cache, state schema, CLI command, or verification bypass.
- `AGENTS.md` is the repository symlink to `CLAUDE.md`; edit only `CLAUDE.md`.
- At this main baseline, `bin/ratbench` and `bench/suite.json` are absent.
  The development branch has a benchmark runner, but the experiment must not
  quietly switch implementation bases or claim its results apply to main.

## Verified implementation surface

- `ratlib.governor.recommend()` is advisory and is currently invoked from
  `bin/rat` only after the 5-action novelty window reports `stuck`.
- Environment-invalidating findings take precedence over active PASS/consumed
  primitives. An evidence-linked active primitive takes precedence over an
  unrelated unknown. Refuted findings/ruled-out routes precede a discriminator.
- Primitive PASS and final SOLVED remain dependent on the existing canonical
  STATE/SELF and deterministic completion gates; this patch changes neither.
- Routine FAST continuation is an instruction-policy change, not a new
  automatic orchestration state machine.

## Deterministic regression gate

```sh
python3 -m unittest tests.test_governor tests.test_governor_continuation \
  tests.test_patterns_v21 tests.test_rat_dispatcher
python3 bin/rat selftest
python3 bin/pklearn selftest
```

The existing `.github/workflows/regression.yml` push checks are the
operational gate. A PR targeting `main` also triggers `analysis-deep`.
Record the workflow run URL and exact head SHA. CI success is a regression
check, **not** evidence of an improved verified solve rate.

## Solve-oriented benchmark gate (not yet executed)

Use an external, isolated agent evaluation harness or separately reviewed
benchmark capability. Fix the following for all A0 and A1 attempts:

1. Challenge corpus, per-artifact digest, oracle and ground truth.
2. Model ID, reasoning effort, agent CLI, tool versions, OS and timeout.
3. Cache mode (report cold and warm separately) and allowed tools.
4. Repeat at least three times per challenge; preserve all outcomes,
   including censored, skipped and infrastructure failures.
5. Never expose challenge solutions, verification inputs or ground truth
   to the agent workspace.

Collect `verified_solve`, `time_to_first_valid_primitive`,
`time_to_verified_solve`, input/output tokens when observer-measured,
tool calls, duplicate tool calls, cache usage and context bytes. Report
`null` for unobservable values rather than infer or fabricate them.
Only the canonical completion gate qualifies a solve as verified.

## Promotion and rollback

- A1 is **not** an improvement until independent measured solve comparisons
  show no correctness regression and an actual cost or completion gain.
- If the Governor picks `focused-deep` on invalidated/absent evidence, or
  suppresses a blocking environment verification, fail the gate.
- If results regress, revert the Governor/advisory instruction commit; do not
  weaken the primitive or verification gate.
- Pattern/lesson retrieval and delegation optimization are separate A2/A3
  changes and must not be bundled into the A1 performance claim.

## Current status

- Implementation: committed to the isolated working branch.
- Automated regression: pending CI evidence at branch head.
- Real verified-solve benchmark: **NOT RUN**.

