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

Validate the local manifest and emit only the intended corpus before running a benchmark:

```sh
PYTHONPATH=bin python3 -m ratlib.bench_suite \
  bench/local-suite.json --corpus private \
  > /tmp/ctf-rat-private-suite.json
```

The command exits non-zero for malformed JSON/schema, unsafe paths, duplicate IDs, invalid metadata, or an empty requested corpus. It does not execute a solver or benchmark. The projected file is consumed by the existing runner:

```sh
python3 bin/ratbench eval \
  --suite /tmp/ctf-rat-private-suite.json \
  --run-id B-private-A0-001 \
  --ablation A0 \
  --agent '<agent-cli using {dir}>'
```

Use a separate projected suite/run ID for each corpus and ablation. Do not mix synthetic fixtures with real/private entries in a solve-rate comparison.

## Measurement rule

Synthetic fixtures are regression tests, not evidence of real solve rate. Compare architecture changes on the same held-out corpus, model, reasoning effort, environment, timeout, and tool versions. Use benchmark-v2 output for verified solve and latency/tool metrics; leave unavailable telemetry as `null` rather than substituting zero. A real/private baseline is not considered measured until the local artifacts and the external Mode B agent CLI actually execute under this protocol.
