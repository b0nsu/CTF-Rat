# ctf-rat — Codex FAST-path entry

CTF-Rat is a local-first pwn/rev solving kit. The default goal is **time-to-first-action with bounded context** while keeping strict evidence gates for any SOLVED claim.

## Scope and hard invariants

- Work on the provided challenge artifacts, local process/Docker/loopback, and only a **single remote host:port explicitly supplied by the user**.
- Never discover or scan additional targets, brute-force accounts, collect real credentials, persist, evade detection, exfiltrate unrelated data, or DoS infrastructure.
- Do not claim a flag, exploit, primitive, offset, or remote success without concrete reproducible evidence.
- A pwn hypothesis is not a primitive. Do not chain an unverified primitive into an exploit.
- Remote-sensitive assumptions (libc/loader/seccomp/kernel/allocator/protocol state) require explicit validation before a remote success claim.
- Repository writes/pushes happen only when the user explicitly asks for repository changes.

## Default solve path: FAST

**Do not preload doctrine or the knowledge tree. Do not read broad reference files at startup.** Start acting on the artifact.

1. If this is a new challenge, acquire the single-challenge guard once: `ctfguard begin <name>`.
2. Route cheaply: `rat route <artifact>`.
3. Follow **one** bounded next query:
   - rev: `revq <bin> --interesting`, then `rat func <bin> <candidate>`; decompile only a named function when needed.
   - pwn: `recon <bin>` or the specific small pwn helper suggested by the evidence.
   - when a deterministic query is expensive or likely to repeat, use `rat-adapt --root . --emit stdout <tool> ...` so the structured cache can replay the result without re-running the tool.
4. Form the smallest testable hypothesis and run a concrete test/oracle.
5. Repeat bounded queries. Prefer deterministic tool output over prose summaries.
6. Before re-reading accumulated state, use `rat snapshot --root . --budget-bytes 6000` rather than loading full history.
7. Claim SOLVED only after executable/concrete verification. For rev, recovered input must be rerun against the real binary. For pwn, the required primitive and final behavior must be demonstrated in the relevant environment.

FAST is intentionally shallow: route → query → test → verify. No mandatory P0-P5 ceremony, fan-out, skeptic, full Ghidra dump, or broad knowledge loading occurs on this path.

## Escalate to DEEP only when needed

Enter the existing strict orchestration when any of these is materially true:

- FAST signals conflict or remain ambiguous after bounded tests.
- Packed, anti-debug, dynamic-only, VM/obfuscation, or environment-sensitive behavior invalidates static assumptions.
- A pwn primitive must be proven before chaining.
- Local/remote equivalence matters.
- Repeated failed hypotheses make explicit evidence/state bookkeeping cheaper than continuing ad hoc.

On escalation, use the existing `rat-phase` / `rat-task` / `state` / verifier flow. Then load only the doctrine needed for the current gate:

- solving mechanics: `doctrine/SOLVING.md`
- primitive proof: `doctrine/PRIMITIVE_GATE.md`
- solvability/stop decision: `doctrine/SOLVABILITY.md`
- topic knowledge: use `knowledge/GROUNDING_INDEX.md` to select **one relevant knowledge file**, not the whole tree
- writeup/handoff only after solving: `doctrine/WRITEUP_FORMAT.md`

Do not create a second DEEP engine.

## Context discipline

- Keep a normal tool result below roughly 2k model-visible tokens when possible; narrow the query instead of dumping more output.
- Use `rat func`/`revq --func` before a full decompile. Decompile one named function at a time unless evidence requires more.
- Never `cat` large binaries, logs, decompiler exports, state history, or reference trees into context.
- FAST uses the main agent. Do not fan out by default. A scout is justified only when a necessary raw read cannot be reduced to a bounded deterministic query; return conclusions plus evidence locators, not the raw dump.
- Avoid repeating a deterministic tool call with the same effective inputs. Check structured cache, legacy sidecar, and state first.
- Keep facts, hypotheses, and verified primitives distinct. Store only durable findings that prevent re-derivation.

## Minimal command surface

```text
rat route <artifact>                     cheap deterministic routing
rat func <bin> <func|addr>               bounded function card
rat snapshot --root . --budget-bytes N   bounded typed-state projection
rat-adapt --root . --emit stdout ...     structured-cache wrapper for repeatable queries
revq <bin> --interesting                 rev candidate selection
recon <bin>                              pwn triage
decomp <bin> <func>                      named-function decompile
state ...                                durable evidence/hypothesis/primitive state
```

Use other `bin/` tools only when the current evidence calls for them; do not enumerate or probe the whole toolkit first.

## Verification policy

Speed optimizations stop at the verification boundary.

- Heuristics and FAST routing signals never auto-promote to facts or primitive PASS.
- A deterministic executable oracle can replace an LLM skeptic when it directly proves the claimed rev result.
- Remote/environment-sensitive pwn remains strict: validate primitive, environment assumptions, and observed final behavior before claiming success.
- Actual output/log/flag bytes are evidence; inferred success is not.

## Benchmark mode

When measuring an ablation, wrap top-level agent tool calls with `rat-metrics` as documented in `docs/MEASUREMENT.md`. Do not enable telemetry for ordinary solving unless measurement is requested.

The architecture rationale and escalation details live in `docs/CODEX_FAST_PATH.md`; they are reference material, not mandatory startup reading.
