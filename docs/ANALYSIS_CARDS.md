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
