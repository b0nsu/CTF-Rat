# Analysis Card projection policy

CTF-Rat keeps long-lived truth in deterministic artifacts and STATE. Model context is only a bounded working set. Analysis Cards are therefore projections, not a second evidence database.

## Existing REV card

`revq` already emits `rat.function-card/v2`, and `rat query func` projects one function's callers, callees, strings, compare/oracle hints, unresolved items, and provenance through the canonical `rat.query-result/v1` envelope.

## PWN capability projection

`rat query pwn <binary>` is the canonical front door for the equivalent PWN projection. Internally it reuses `ratlib.cards.project_pwn_capability(profile)` and the existing `rat-profile` + deterministic router; it does not introduce another analyzer, cache, state database, or evidence schema.

The query projects only deterministic binary-profile facts:

- ELF protections (`NX`, `PIE`, canary, RELRO) when present in the profile;
- grouped imported sink APIs (unbounded/bounded overflow, format, heap, kernel, input, command execution);
- exact import/sink counts.

Example:

```bash
rat query pwn ./chall --format json
rat query pwn ./chall --budget-bytes 4096 --format json
```

The route (`pwn-stack`, `pwn-format`, `pwn-heap`, `pwn-rop`, `pwn-kernel`) stays under `heuristics.candidate_routes`. API presence never proves that the callsite is unsafe. Output lists are bounded by the query budget while `sink_counts` remain exact.

The projection MUST NOT claim RIP/PC control, arbitrary read/write, a stable leak, heap overlap/reuse, or a kernel object primitive. Those are runtime primitive claims and remain canonical in STATE v2, where PASS promotion requires deterministic direct evidence.

## Route and slice evidence boundaries

High-priority packing observations select an unpacking action, not an exclusive underlying problem class. `rat route` retains independently recovered PWN/checker/VM candidates in `dimensions` and `unresolved`. Kernel-import hints with competing PWN/REV candidates remain `provisional` instead of locking a kernel-specific skill.

`rat query slice` reports a bounded VEX/CFG survey, not a complete def-use proof. Its `heuristics.claim` is `dependency-candidate`, `heuristics.source_to_target_proven` is `false`, and the query stays `partial` / `coverage.complete=false` even when the observed unresolved counters happen to be zero. `--source` is a search hint, not authenticated source-to-target provenance. Use a separate deterministic oracle before promoting a dependency hypothesis to a verified claim.

## Intended canonical flow

```text
binary
  -> rat-profile / revq deterministic artifacts
  -> rat query func | rat query pwn
  -> bounded Function/Capability projection
  -> model hypothesis
  -> targeted experiment
  -> STATE v2 primitive lifecycle
  -> rat-verify / executable oracle
```

Do not automatically inject every card into context. The router/query front door should request the minimum card needed for the current hypothesis.
