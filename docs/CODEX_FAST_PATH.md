# Codex FAST Path

This document defines the low-context hot path introduced by `bin/rat`.
It complements the existing strict P0-P5 orchestration; it does not replace it.

## Goal

Minimize context and ceremony per decision while preserving CTF-Rat's evidence model for cases that actually need it.

The default solve loop becomes:

```text
artifact
  -> rat route
  -> one bounded tool query
  -> attempt / executable oracle
  -> repeat
  -> DEEP only when an escalation trigger fires
```

## Commands

### Route

```bash
rat route ./chall
rat route ./chall --json
rat route ./chall --category rev
```

`route` performs cheap local fingerprinting only. It reports:

- file type and SHA-256
- rev/pwn routing signals
- current revq/decomp/structured-cache status
- a small ordered `NEXT` list
- explicit DEEP escalation triggers

It deliberately does **not** create phase state, hypotheses, primitives, or skeptic tasks.

### Function card

```bash
rat func ./chall verify_input
rat func ./chall 0x401240 --json
```

This delegates to the existing `revq --func` implementation rather than creating another analysis engine. The purpose is a stable front-door command for Codex and a future place to evolve the function-card schema.

### Context snapshot

```bash
rat snapshot --root . --budget-bytes 6000
rat snapshot --root . --budget-bytes 6000 --json
```

This reads the existing typed `Stream` view and projects only model-relevant state. The full append-only state remains authoritative; the snapshot is only a bounded context projection.

## FAST -> DEEP escalation

Enter the existing strict orchestration only when one or more conditions apply:

1. FAST signals conflict or remain materially ambiguous.
2. Packed, anti-debug, dynamic-only, or environment-sensitive behavior invalidates static assumptions.
3. A pwn primitive must be proven before it is chained into an exploit.
4. Local/remote runtime equivalence matters (libc, loader, seccomp, kernel, allocator, protocol state).
5. The same hypothesis has failed enough times that explicit hypothesis/primitive bookkeeping will prevent repeated work.

When escalation is needed, keep using the existing tools (`rat-phase`, `rat-task`, `rat-context`, `state`, verifier/skeptic flow). Do not implement a second DEEP engine.

## Cache policy

`rat route` currently exposes three cache layers without changing their formats:

- `revq`: `<binary>.revq.json`
- `decomp`: `<binary>.decomp` with provenance metadata
- structured contract cache: `.rat/indexes/cache.sqlite3`

This first slice intentionally does **not** migrate cache formats. The next cache milestone should make the structured cache the canonical index and register revq/decomp artifacts into it while retaining compatibility with the existing sidecars during migration.

## Design constraints

- Local/read-only by default.
- Deterministic routing; no model call is required to classify the first step.
- Bounded output suitable for Codex context.
- Reuse existing `revq`, `recon`, `rat-doctor`, `state_v2`, and strict orchestration.
- Do not weaken primitive or environment validation once DEEP mode is entered.
- Do not auto-promote heuristic FAST observations to evidence.

## Planned follow-up

### P0

- Measure `rat route` latency and output bytes in benchmark fixtures.
- Extend benchmark-result schema with input/output/cache/tool timing fields.
- Integrate `revq` and `decomp` provenance into the structured cache index.
- Replace mandatory broad startup reading in agent instructions with: route -> load one relevant skill -> bounded query.

### P1

- Function Card v2: callers/callees, compare sites, branch summaries, stack/data dependencies, oracle distance, next-query hints.
- Backward data slice from compare/branch/output sinks.
- Oracle detector that emits find/avoid targets for symbolic solving.
- Differential trace between two inputs to locate first control-flow divergence.
- Input dependency map.

### P2 (only if benchmarked as bottlenecks)

- syscall/seccomp observer
- allocator event collector
- coverage-guided fuzz adapter
- replay/record tooling

## Benchmark gate

Use ablations rather than subjective impressions. Recommended sequence:

```text
A0 current main
A1 + bin/rat FAST front door
A2 + bounded startup instructions
A3 + canonical cache index
A4 + Function Card v2
A5 + backward slice / oracle detector
A6 + conditional DEEP policy
```

Track at minimum:

- verified solve rate
- time to flag
- total input/output tokens
- peak model-visible context
- tool calls and duplicate tool calls
- cache hit/read/write counts
- wall time in tools vs model/API
- number of DEEP escalations

A feature should stay on the default hot path only when it improves solve rate or time-to-flag without a disproportionate context/tool-cost regression.
