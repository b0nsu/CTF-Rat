# Google CTF 2024 — NotObfuscated

This fixture represents the published **NotObfuscated** reversing challenge from Google CTF 2024 Quals.

The challenge binary is intentionally **not committed** here. Materialize the exact published attachment before a real Mode B run:

```sh
PYTHONPATH=bin python3 -m ratlib.bench_artifacts \
  bench/suite.json --corpus real --id google-ctf-2024-notobfuscated
```

The canonical suite entry pins the official `google/google-ctf` attachment by Git blob SHA-1. The upstream repository and challenge source are Apache-2.0 licensed.

Upstream provenance:

- repository: `google/google-ctf`
- challenge: `2024/quals/rev-notobfuscated`
- published attachment: `2024/quals/rev-notobfuscated/attachments/challenge`
- license: Apache-2.0

The committed `route.json` is a bounded router-compatibility fixture based only on the public success/failure oracle strings. It is **not** a live analyzer transcript, a recovered input, or solve-rate evidence. Mode B routing telemetry from the answer-free runtime is the measurement source for real runs.

Do not copy upstream source, `metadata.yaml`, solutions, healthchecks, known-good input, flag material, or other answer-bearing files into this fixture or the Mode B runtime export. Only the pinned challenge attachment is materialized.
