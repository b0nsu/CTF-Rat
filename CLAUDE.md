# ctf-rat — Codex FAST path

CTF-Rat is a local-first pwn/rev kit. Optimize for **time-to-first-action and bounded context**, but never weaken the evidence required for a SOLVED claim.

## Hard invariants

- Work only on supplied challenge artifacts, local process/Docker/loopback, and a single remote host:port explicitly supplied by the user.
- Do not discover/scan extra targets, brute-force accounts, collect real credentials, persist, evade detection, exfiltrate unrelated data, or DoS infrastructure.
- Never claim a flag, exploit, primitive, offset, or remote success without reproducible evidence.
- A pwn hypothesis is not a primitive. Do not chain an unverified primitive.
- Validate remote-sensitive libc/loader/seccomp/kernel/allocator/protocol assumptions before a remote success claim.
- Modify/push the repository only when explicitly requested.

## Default: FAST

**Do not preload doctrine, knowledge, or broad references. Touch the artifact first.**

1. New challenge: acquire the single-challenge guard once with `ctfguard begin <name>`.
2. Route: `rat route <artifact>`.
3. Run one bounded query:
   - rev: `revq <bin> --interesting` → `rat-func-v2 <bin> <candidate>`.
   - if the card exposes success/failure signals: `rat-oracle <bin> --command ...` to produce a cache-aware `symsolve` find/avoid command.
   - decompile only one named function when the remaining question requires code.
   - pwn: `recon <bin>` or one evidence-driven helper.
   - expensive/repeatable deterministic query: use `rat-adapt --root . --emit stdout ...` so structured cache can replay it.
4. Form the smallest testable hypothesis and run a concrete test/oracle.
5. Repeat bounded queries; prefer deterministic facts over prose summaries.
6. Re-read state through `rat snapshot --root . --budget-bytes 6000`, not full history.
7. Claim SOLVED only after concrete verification. Re-run recovered rev input against the real binary; for pwn, demonstrate the primitive and final behavior in the relevant environment.

FAST = route → query → test → verify. No mandatory P0-P5 ceremony, fan-out, skeptic, full decompiler dump, or broad knowledge load.

## Escalate to DEEP only when needed

Escalate when FAST remains ambiguous, anti-analysis/packing/VM/dynamic behavior invalidates static assumptions, a pwn primitive must be proven, local/remote equivalence matters, or repeated failed hypotheses make explicit evidence bookkeeping cheaper.

Use the existing `rat-phase` / `rat-task` / `state` / verifier flow. Load only the doctrine needed now:

- `doctrine/SOLVING.md` — solving mechanics
- `doctrine/PRIMITIVE_GATE.md` — primitive proof
- `doctrine/SOLVABILITY.md` — stop/solvability decision
- `knowledge/GROUNDING_INDEX.md` — choose one relevant knowledge file
- `doctrine/WRITEUP_FORMAT.md` — only for final handoff/writeup

Do not create a second DEEP engine.

## Context discipline

- Keep normal model-visible tool output around <=2k tokens; narrow the query instead of dumping more.
- Prefer `rat-func-v2` before decompilation. Decompile one named function at a time.
- Never dump large binaries, logs, decompiler exports, state history, or reference trees into context.
- FAST stays in the main agent. No default fan-out. Use a scout only when a necessary raw read cannot be reduced to a bounded deterministic query.
- Do not repeat deterministic calls with the same effective inputs. Check structured cache/state first.
- Keep facts, hypotheses, oracle candidates, and verified primitives distinct.

## Minimal command surface

```text
rat route <artifact>                     cheap deterministic routing
rat-func-v2 <bin> <func|addr>           structured Function Card v2
rat-oracle <bin> --command ...           success/failure xref → symsolve wiring
rat snapshot --root . --budget-bytes N   bounded typed-state projection
rat-adapt --root . --emit stdout ...     structured-cache wrapper
revq <bin> --interesting                 rev candidate selection
recon <bin>                              pwn triage
decomp <bin> <func>                      named-function decompile
state ...                                durable evidence state
```

Other tools are lazy-loaded only when current evidence calls for them.

## Verification boundary

- FAST routing, role labels, oracle strings, and xref anchors are candidates, not proof.
- `rat-oracle` may wire deterministic xref anchors into `symsolve`, but the recovered solution must still pass concrete execution.
- A deterministic executable oracle can replace an LLM skeptic for a directly proven rev result.
- Remote/environment-sensitive pwn remains strict.
- Actual output/log/flag bytes are evidence; inferred success is not.

## Benchmark mode

For ablations, use `rat-metrics` per `docs/MEASUREMENT.md`. Telemetry is opt-in for benchmark runs, not normal solving.

Architecture details live in `docs/CODEX_FAST_PATH.md`; they are not startup reading.
