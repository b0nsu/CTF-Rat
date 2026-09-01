# ratbench corpus manifest

`bench/suite.json` defines the canonical manifest shape for synthetic, integration, real, and private/held-out benchmark entries. Do not create a second benchmark database for real challenges. For non-redistributable local evaluation, use an ignored local suite with the same schema and pass it through the existing `ratbench --suite` interface.

## Corpus classes

- `synthetic` — repository-authored deterministic fixtures; safe to commit.
- `integration` — repository-authored or explicitly redistributable noisy fixtures used to exercise multiple tools together.
- `real` — real competition challenge material. Commit binaries only when redistribution rights are explicit.
- `private` — held-out/local evaluation material. Keep challenge artifacts and local manifest metadata out of git when redistribution is not allowed.

Every entry declares:

- `corpus`: one of the classes above.
- `capabilities`: unique kebab-case tags describing the capability exercised, not a claimed exploit result.
- `redistributable`: whether the challenge artifact itself may be committed.

The committed suite is checked by `tests/test_bench_suite_manifest.py` using `ratlib.bench_suite.validate_suite`. Invalid IDs, duplicate entries, path escapes, invalid corpus values, malformed capability tags, and entries without a source or binary are rejected.

## Adding a held-out entry

For non-redistributable material, create an ignored `bench/local-suite.json` (or `bench/heldout-suite*.json`) rather than editing the committed suite. Entries still use paths relative to `CTF_HOME`, so challenge artifacts may stay under the ignored `bench/artifacts/` tree while the suite itself remains local.

```json
{
  "schema": "rat.bench-suite/v1",
  "entries": [
    {
      "id": "heldout-example-01",
      "track": "rev",
      "expected_route": "rev-checker",
      "difficulty": 3,
      "corpus": "private",
      "capabilities": ["checker", "stripped"],
      "redistributable": false,
      "dir": "bench/artifacts/heldout-example-01",
      "binary": "chall.bin",
      "route_fixture": "route.json",
      "verify": {"kind": "rat-verify-pass"},
      "env": {"needs_libc": false}
    }
  ]
}
```

Place `chall.bin` locally under that directory; `bench/.gitignore` excludes `artifacts/**/*.bin`, local suite manifests, and inherited `.rat` state. Do not commit flags, known-good inputs, prior `.rat` state, or other answer material into an agent-visible runtime fixture. Mode B exports only the challenge runtime artifacts allowed by the existing answer-free workspace rules.

## Fail-closed preflight and corpus projection

`ratbench run/eval` validates the suite and applies `--corpus` before route/oracle/agent execution. A missing requested corpus is an error, not a zero-entry benchmark.

For an explicit standalone preflight, the same canonical implementation can emit a projected suite without executing anything:

```sh
PYTHONPATH=bin python3 -m ratlib.bench_suite \
  bench/local-suite.json --corpus private \
  > /tmp/ctf-rat-private-suite.json
```

The command exits non-zero for malformed JSON/schema, unsafe paths, duplicate IDs, invalid metadata, or an empty requested corpus. Direct Mode B execution can use the local suite without an intermediate file:

```sh
python3 bin/ratbench eval \
  --suite bench/local-suite.json \
  --corpus private \
  --run-id B-private-001 \
  --ablation A0 \
  --model-id '<model label>' \
  --reasoning-effort '<effort label>' \
  --agent '<agent-cli using {dir}>'
```

Use a separate run ID when measurement conditions change. Do not mix synthetic fixtures with real/private entries in a solve-rate comparison.

## Benchmark-v2 provenance

Current Mode B producers attach a `provenance` object to every `rat.benchmark-result/v2` row. It records:

- SHA-256 of the exact validated post-filter suite execution set;
- selected corpus class(es);
- agent executable name and SHA-256 of the exact agent command template (the raw command is not stored);
- optional `--model-id` and `--reasoning-effort` labels;
- timeout and whether observer-owned `execve` tracing was available;
- OS, architecture, and Python runtime identity;
- CTF-Rat revision and schema-bundle identity.

If `CTF_RAT_REVISION` is set it is authoritative; otherwise a clean git checkout records `HEAD`, a dirty checkout appends a content-derived dirty digest, and exports without git metadata fall back to `worktree`. Historical benchmark-v2 rows without provenance remain readable for compatibility. `ratbench report --schema v2` fails closed if rows under the same `benchmark_run_id` contain mixed provenance, including across ablations, rather than aggregating incomparable attempts.

## Benchmark-v2 routing projection

Live Mode B rows also attach an optional top-level `routing` object derived from the existing STATE `route-assessment` notes. It is observer-readable telemetry, not ground truth and not a reconstructed classification. Historical benchmark-v2 rows without this projection remain valid.

The projection records:

- `first_route` and `first_route_commitment`;
- whether the first assessment had a conflict and how many primary/alternative candidates were visible;
- total route assessments and actual route revisions;
- the first route-specific skill that was locked, if any.

An attempt that never ran the routing front door reports `route_assessment_count=0` and leaves all first-route fields `null`; it must not fabricate an `unknown` route after the fact. This makes hard-route versus active-triage runs directly inspectable without treating a route label as solve correctness.

## Architecture ablation rule

`--ablation A0|A1|...` is a **measurement label only**. It does not secretly change router behavior, prompts, model configuration, or runtime policy. An architecture ablation must change one real implementation/configuration variable and be reproduced under otherwise identical conditions.

For routing studies, prefer revision-based ablation over hidden runtime switches:

1. run the hard-route baseline revision on one held-out corpus with a unique `benchmark_run_id`;
2. run the active-triage revision on the same corpus/model/reasoning effort/environment/timeout/toolchain except for the intended CTF-Rat revision;
3. label the rows consistently (for example baseline `A0`, active-triage `A1`) while relying on `provenance.toolchain.ctf_rat_revision` as the authoritative implementation identity;
4. compare `verified_solve` and latency/tool metrics together with the `routing` projection (`first_route_commitment`, conflict rate, route revisions, first skill lock).

Do not reuse one `benchmark_run_id` across different revisions: provenance validation intentionally fails closed on mixed measurement conditions. Synthetic Mode A route accuracy may guard compatibility, but it is not evidence that one routing architecture solves real challenges better.

## Measurement rule

Synthetic fixtures are regression tests, not evidence of real solve rate. Compare architecture changes on the same held-out corpus, model, reasoning effort, environment, timeout, and tool versions. Use benchmark-v2 output for verified solve and latency/tool metrics; leave unavailable telemetry as `null` rather than substituting zero. Provenance improves reproducibility but does not manufacture unavailable dependency/tool-version telemetry. A real/private baseline is not considered measured until the local artifacts and the external Mode B agent CLI actually execute under this protocol.
