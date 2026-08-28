# ratbench corpus manifest

`bench/suite.json` is the single manifest for synthetic, integration, real, and private/held-out benchmark entries. Do not create a second benchmark database for real challenges.

## Corpus classes

- `synthetic` — repository-authored deterministic fixtures; safe to commit.
- `integration` — repository-authored or explicitly redistributable noisy fixtures used to exercise multiple tools together.
- `real` — real competition challenge material. Commit binaries only when redistribution rights are explicit.
- `private` — held-out/local evaluation material. Keep challenge artifacts out of git and add them locally under the manifest entry's `dir`.

Every entry declares:

- `corpus`: one of the classes above.
- `capabilities`: unique kebab-case tags describing the capability exercised, not a claimed exploit result.
- `redistributable`: whether the challenge artifact itself may be committed.

The committed suite is checked by `tests/test_bench_suite_manifest.py` using `ratlib.bench_suite.validate_suite`. Invalid IDs, duplicate entries, path escapes, invalid corpus values, malformed capability tags, and entries without a source or binary are rejected.

## Adding a held-out entry

Keep the artifact local when redistribution is not allowed:

```json
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
```

Place `chall.bin` locally under that directory; `bench/.gitignore` excludes `artifacts/**/*.bin`. Do not commit flags, known-good inputs, prior `.rat` state, or other answer material into an agent-visible runtime fixture. Mode B exports only the challenge runtime artifacts allowed by the existing answer-free workspace rules.

## Measurement rule

Synthetic fixtures are regression tests, not evidence of real solve rate. Compare architecture changes on the same held-out corpus, model, reasoning effort, environment, timeout, and tool versions. Use benchmark-v2 output for verified solve and latency/tool metrics; leave unavailable telemetry as `null` rather than substituting zero.
