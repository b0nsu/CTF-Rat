# A1b: evidence-conflict Governor hardening

## Scope and provenance

- Parent: PR #79 (A1), head `1132a526d79032a95cf24d1e7e5023b5a78c5147`.
- Changes are restricted to `ratlib.governor.recommend()`, its focused tests,
  and this ablation note. Existing Router v2, STATE v2 schema, PASS proof
  contracts, CLI output types, and deterministic completion gate are unchanged.
- This is **stuck-state advice only**. `bin/rat::_governor_wrap` calls `recommend`
  after the 5-action no-novelty window; the recommendation does not run probes.

## Source-first findings

- `state_v2.Stream._materialize` tracks observation validity, latest finding
  revision, current primitive, and evidence invalidations.
- Real observations have `quality.level` and `validity.state` metadata.
  Typed primitive PASS is validated separately against >=3 distinct active,
  direct SELF observations, artifact provenance, input/environment digests
  and class-specific proof coverage.
- `unknown.recorded` does **not** define a typed primitive dependency.
  Do not infer a blocking prerequisite solely from a shared observation ID.

## A1 -> A1b changes

1. Keep environment rechecks first, but require that an environment finding
   actually cites an observation present in the event stream. Invalidated
   evidence still justifies a recheck.
2. For PASS/consumed advice, reject *explicitly* non-direct or inactive SELF
   observation metadata. Maintain the prior advisory behavior for legacy
   minimal event fixtures missing these fields; never mistake advice for a
   typed PASS validation.
3. If an active observation is cited by both a PASS/consumed primitive and a
   refuted/invalidated finding, recommend `re-route` with both basis IDs
   instead of `focused-deep`. This is a **conservative conflict heuristic**:
   shared evidence is not proof that a finding directly refutes that
   primitive. Unrelated refutations retain the A1 preference for continuation.
4. No new action names, schema fields, DB, CLI, cache or inference graph.

## Verification

Targeted deterministic tests:

```sh
python3 -m unittest tests.test_governor tests.test_governor_continuation \
  tests.test_patterns_v21 tests.test_rat_dispatcher
python3 bin/rat selftest
python3 bin/pklearn selftest
```

The existing `.github/workflows/regression.yml` is the full regression gate.
Record exact head SHA, run URL and status. This patch does not establish an
improved model solve rate merely by passing unit or integration tests.

## Ablation

- A0 = main `517964d3` (before PR #79).
- A1 = PR #79 `1132a526`.
- A1b = this branch's final head.
- Use identical fixed model/reasoning/agent CLI/corpus, verified-completion
  oracle, environment, tools and timeout; at least 3 attempts per challenge.
- Report verified solve rate, false VERIFIED, time to verified solve, redundant
  probe calls, tokens per verified solve and invalid-evidence continuations.
- `main` has no `bin/ratbench`; do not conflate the `dev` benchmark harness
  with a measurement of main. Evaluation remains NOT RUN until an isolated
  external harness or separately reviewed backport is used.

## Risks, migration and rollback

- Sharing a SELF observation does not prove the finding and primitive are
  semantically related. The conservative re-route may increase unnecessary
  pivots; measure this before promotion. If the observed rate regresses,
  revert only the A1b Governor patch.
- A consumed primitive still receives the A1 continuation recommendation
  when no explicit counterevidence exists: detecting terminal consumption
  needs a real next-step dependency contract, not a guessed heuristic.
- A genuine blocking unknown remains unresolved: introducing dependency
  metadata requires a separate schema/contract and ablation decision.
- Rebase/retarget this stacked PR onto `main` after PR #79 merges.
- No implementation or CI success authorizes `SOLVED` without the canonical
  deterministic completion verifier.

## Status

- Focused synthetic tests: locally exercised in a standalone copy.
- Full repository regression/CI: pending independent GitHub Actions evidence.
- Agent-level benchmark: NOT RUN.
