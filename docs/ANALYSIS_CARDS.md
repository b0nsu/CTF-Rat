# Analysis Card projection policy

CTF-Rat keeps long-lived truth in deterministic artifacts and STATE. Model context is only a bounded working set. Analysis Cards are therefore projections, not a second evidence database.

## Existing REV card

`revq` emits `rat.function-card/v4`, and `rat query func` projects one function's callers, callees, strings, call-site records, compare/oracle hints, unresolved items, and provenance through the canonical `rat.query-result/v1` envelope. Angr-backed call-site records distinguish the CFG block address from the actual call instruction address, retain repeated calls to the same API, identify the loader virtual-address space and analysis source, and report unresolved decoding/targets explicitly. For direct comparison calls, v4 recovers a length only on ELF AMD64 System V when the last same-basic-block definition of `rdx`/`edx` is a supported literal. Each comparison reports `constant`, `not_applicable`, `value_unresolved`, or `unsupported_abi`; an address may therefore be recovered while its length remains unresolved. Query-budget omissions include exact `call_sites` and `compare_sites` counts.

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

PWN import-derived attention leads (`pwn-stack`, `pwn-format`, `pwn-heap`, `pwn-rop`, `pwn-kernel`) stay under `heuristics.candidate_routes` for compatibility, with no locally fabricated confidence or primary winner. The PWN card does not re-run the router on a profile-only subset. `heuristics.next` provides independent bounded probe options rather than a compulsory sequence. API presence never proves that the callsite is unsafe. Output lists are bounded by the query budget while `sink_counts` remain exact.

The projection MUST NOT claim RIP/PC control, arbitrary read/write, a stable leak, heap overlap/reuse, or a kernel object primitive. Those are runtime primitive claims and remain canonical in STATE v2, where PASS promotion requires deterministic direct evidence.

## Route and slice evidence boundaries

Packing observations suggest a bounded check of the packing obstacle, not an exclusive program class or a proven unpacking requirement. `rat route` retains independently recovered PWN/checker/VM observations in `dimensions`, `leads` and `unresolved`. Coexisting leads do not imply `conflict`: a checker and a memory-safety surface can both be present. All static-only routes, including kernel-import and checker-call routes, remain `provisional` without locking a route-specific skill. Numeric `confidence` and singular `subroute` are legacy compatibility data, not probability or verified classification.

`rat query slice` reports a bounded VEX/CFG survey, not a complete def-use proof. Its `heuristics.claim` is `dependency-candidate`, `heuristics.source_to_target_proven` is `false`, and the query stays `partial` / `coverage.complete=false` even when the observed unresolved counters happen to be zero. `--source` is currently recorded as a requested source label by the producer; it does not constrain the VEX scan or establish source-to-target provenance. Use a separate deterministic oracle before promoting a dependency hypothesis to a verified claim.

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


## Global REV call graph (bounded projection)

`rat query graph <binary>` gives the model a compact **whole-binary call-map view**
without passing `objdump -d` or every Ghidra decompilation through its context.
It reuses the same `revq` extracted function map and cache as `rat query func`;
it does **not** run a second graph-analysis backend.

```bash
rat query graph ./chall
rat query graph ./chall --max-nodes 32 --budget-bytes 8192
rat query graph ./chall --format json
rat query graph ./chall --fast  # ELF/binutils: missing call edges are explicitly partial
rat query func ./chall check_password
decomp ./chall check_password
```

The first invocation may run angr CFGFast; subsequent calls reuse revq's existing
cache for the same binary/analysis engine. `--max-nodes` and
`--budget-bytes` bound the model-visible **node projection**, not the
on-disk full revq map. The byte budget is approximate and reserves space for
metadata; it is not a hard cap on the entire JSON/text response. Nodes are
never cut mid-record. If functions or edges are omitted, `coverage.complete`
is false and `coverage.omitted` describes omitted recovered functions and
internal edges from visible nodes. Increase the budget or query one function
for detail; never equate the visible subgraph with the whole binary.

Node IDs are recovered function addresses. Named callees are resolved to
internal edges only when exactly one recovered function has that name.
`named_targets` may include imports, PLT stubs, or functions not recovered
in this map: they are **not** asserted to be external. Ambiguous same-name
callees are reported, not linked arbitrarily. `--fast` produces only
symbol-level information. Indirect calls cannot currently be enumerated
from revq's function-name list.

This output is a **recovered call map**, not a basic-block CFG, a value-flow
proof, or a feasible execution-path proof. Function ordering uses existing
revq interesting-function scores to prioritize the visible graph; these
scores are selection heuristics, not vulnerability findings. Exact
assembly/decompilation remains available through existing tools.
