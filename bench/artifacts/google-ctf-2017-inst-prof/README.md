# Google CTF 2017 — Inst Prof

This fixture represents the published **Inst Prof** pwn challenge from Google CTF 2017 Quals.

The challenge binary is intentionally **not committed** here. Materialize the exact published attachment before a real Mode B run:

```sh
PYTHONPATH=bin python3 -m ratlib.bench_artifacts \
  bench/suite.json --corpus real --id google-ctf-2017-inst-prof
```

The canonical suite entry pins the official `google/google-ctf` attachment by Git blob SHA-1. The upstream repository is licensed under Apache-2.0, and the original source carries the same license notice.

Upstream provenance:

- repository: `google/google-ctf`
- challenge: `2017/quals/2017-pwn-inst-prof`
- published attachment: `2017/quals/2017-pwn-inst-prof/attachments/inst_prof`
- license: Apache-2.0

Do not copy upstream `flag.txt`, README flag material, healthcheck/solution content, or other answer material into this fixture. Mode B should expose only the pinned challenge runtime artifact.
