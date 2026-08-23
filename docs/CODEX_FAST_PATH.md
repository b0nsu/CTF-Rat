# Codex FAST Path

This document defines CTF-Rat's low-context hot path. It complements the strict P0-P5 orchestration; it does not replace the evidence model used when a solve claim actually needs it.

## Goal

Minimize time-to-first-action, repeated analysis, and model-visible context per decision while preserving concrete verification.

```text
artifact
  -> rat route
  -> one bounded deterministic query
  -> smallest test / executable oracle
  -> repeat
  -> DEEP only when an escalation trigger fires
```

The agent entrypoint intentionally does **not** preload doctrine, the knowledge tree, the full tool catalog, or STATE history.

## FAST commands

### Route

```bash
rat route ./chall
rat route ./chall --json
rat route ./chall --category rev
```

`route` performs cheap local fingerprinting only. It reports file/hash signals, rev/pwn routing hints, current cache visibility, a small ordered `NEXT` list, and explicit DEEP triggers. It deliberately does not create phase state, hypotheses, primitives, or skeptic tasks.

### Function Card v2

```bash
rat-func-v2 ./chall verify_input
rat-func-v2 ./chall 0x401240 --format json
```

Function Card v2 reuses the existing `revq --json` facts through the structured cache. It reports callers/callees, compare/input calls, role signals, lexical oracle signals, and call-graph oracle distance. Fields that require branch/value/stack analysis remain empty with explicit coverage notes rather than being guessed.

### Oracle candidates

```bash
rat-oracle ./chall
rat-oracle ./chall --command --stdin 16 --printable
```

`rat-oracle` classifies unambiguous lexical success/failure strings. `revq` string-xref instruction addresses remain evidence locators only: an xref may be in the middle of an angr block, so it is not automatically promoted to a safe `--find/--avoid` control-flow target. Generated `symsolve` commands prefer `--find-str/--avoid-str`, which also keeps concrete re-execution verification enabled.

### Experimental bounded backward slice (A5 candidate)

```bash
rat-bslice ./chall check 0x401234
rat-bslice ./chall check 0x401234 --json
```

The anchor may be an instruction/xref inside a target CFG block. `rat-bslice` examines in-function predecessor-block VEX Exit guards, resolves temporary and same-block register definitions, and recognizes direct stack-base plus constant slots. It explicitly reports whether reaching the anchor block requires the branch to be `taken` or `must-not-take`.

It does **not** claim inter-block value flow, memory alias resolution, or whole-program taint. Keep it experimental until A5 benchmarks show measurable value.

### Context snapshot

```bash
rat snapshot --root . --budget-bytes 6000
rat snapshot --root . --budget-bytes 6000 --json
```

The full append-only state remains authoritative. The snapshot is only a bounded model-context projection.

### Transparent structured-cache query

For deterministic queries that may be repeated, use the existing adapter as a transparent cache wrapper:

```bash
rat-adapt --root . --emit stdout revq ./chall --interesting
rat-adapt --root . --emit stdout revq ./chall --func check
rat-adapt --root . --emit stdout decomp ./chall check
rat-adapt --root . --emit stdout recon ./chall
```

Existing file arguments are automatically included as semantic cache inputs. The first execution stores a `rat.tool-result/v1` envelope and stdout/stderr artifacts under `.rat`; an identical successful non-truncated query can then replay stdout without invoking the underlying tool. `--cache-meta` exposes hit/key information on stderr when debugging benchmarks.

Direct `revq` and `decomp` remain compatible and retain their legacy sidecars during migration. The adapter is the current path to the canonical structured index; do not create another cache implementation.

## FAST -> DEEP escalation

Enter the existing strict orchestration only when one or more conditions are materially true:

1. FAST signals conflict or remain ambiguous after bounded tests.
2. Packed, anti-debug, VM/obfuscated, dynamic-only, or environment-sensitive behavior invalidates static assumptions.
3. A pwn primitive must be proven before chaining.
4. Local/remote runtime equivalence matters (libc, loader, seccomp, kernel, allocator, protocol state).
5. Repeated failed hypotheses make explicit hypothesis/primitive bookkeeping cheaper than continuing ad hoc.

On escalation, keep using the existing `rat-phase`, `rat-task`, `rat-context`, `state`, verifier, and skeptic machinery. Load only the doctrine needed for the current gate. Do not implement a second DEEP engine.

## Cache policy

There are currently three legacy/structured views:

- `revq`: `<binary>.revq.json`
- `decomp`: `<binary>.decomp` with provenance metadata
- canonical structured query cache: `.rat/indexes/cache.sqlite3` pointing to immutable `.rat` artifacts

Migration policy:

1. Keep revq/decomp sidecars readable so existing workflows do not break.
2. Prefer `rat-adapt --emit stdout` for repeatable expensive queries so the structured index can short-circuit the entire legacy tool invocation.
3. Measure structured cache reads/hits/writes through `rat-metrics`.
4. Do not delete sidecars until benchmarks show the structured path covers required workflows and provenance.
5. Do not cache failed, timed-out, partial, or truncated results as reusable analysis.

The current telemetry cache ratio is therefore the **structured query cache ratio**, not yet a repository-wide union of every legacy sidecar hit.

## Context discipline

- Normal query output should stay around 2k model-visible tokens when possible; narrow instead of dumping.
- Prefer function cards before full decompile; decompile one named function at a time.
- Do not inject full logs, decompiler directories, STATE history, or reference trees into the model.
- FAST uses the main agent and does not fan out by default.
- A scout is justified only when a necessary raw read cannot be reduced to a bounded deterministic query; return conclusions and evidence locators rather than raw output.
- Check cache/state before repeating an equivalent deterministic query.

## Verification invariants

- Heuristic route signals, function roles, oracle strings, xref locators, and bounded slices never auto-promote to facts or primitive PASS.
- Rev recovery must be concretely rerun against the real binary before SOLVED.
- A deterministic executable oracle can replace an LLM skeptic when it directly proves the rev claim.
- Environment-sensitive pwn remains strict: primitive, assumptions, and observed final behavior must be validated in the relevant environment.
- Actual output/log/flag bytes are evidence; inferred success is not.

## Measurement

`rat-metrics` is opt-in. The reproducible workflow is in `docs/MEASUREMENT.md`.

Track at minimum:

- verified solve rate
- time to flag / time to verified
- input/output/cache tokens when exposed by the model harness
- peak model-visible context
- top-level tool calls and duplicate calls
- structured-cache reads/hits/writes
- tool wall time vs model/API wall time
- DEEP escalation count

Run each comparable challenge/ablation at least three times. Correctness is the first gate; speed/context improvements do not justify lower verified solve rate.

## Ablation sequence

The existing benchmark contract accepts A0-A5. Keep the sequence within that contract unless the benchmark schema/manifests are deliberately versioned together.

```text
A0 current/main baseline
A1 + FAST front door
A2 + bounded startup instructions / lazy doctrine
A3 + transparent structured query cache
A4 + Function Card v2 + lexical oracle wiring
A5 + experimental bounded backward slice
```

Conditional DEEP is a policy exercised across A2+ rather than a separate unsupported A6 label.

## Implementation status

- [x] FAST front door (`rat route`, `rat func`, `rat snapshot`)
- [x] opt-in benchmark telemetry
- [x] bounded Codex startup instructions
- [x] transparent structured-cache adapter for revq/recon/gdbq/symsolve/decomp
- [x] Function Card v2 with stable structured fields and explicit coverage gaps
- [x] conservative oracle detector; xrefs stay locators, generated solving uses lexical output conditions
- [x] bounded predecessor-block backward slice as an experimental A5 query

### Only if benchmarks identify a bottleneck

- differential trace
- syscall/seccomp observer
- allocator event collector
- coverage-guided fuzz adapter
- replay/record tooling

A feature stays on the default hot path only when it improves verified solve rate or time-to-flag without a disproportionate context/tool-cost regression.
