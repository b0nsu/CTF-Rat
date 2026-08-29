# Desktop v0.3 — bounded analysis control

## Status

This v0.3 slice adds bounded control, query, and evidence-navigation surfaces without turning Desktop into a second solver, decompiler, verifier, state store, or generic command runner.

## Canonical path

```text
run.json (rat.run/v1)
        |
        | binary/libc identity + sha256
        v
Desktop AnalysisManager
        |
        | fixed argv only
        v
rat brief --fast                         (FAST)
rat brief                                (DEEP)
rat query func ... --fast                (Function Card)
rat query oracle ... --fast              (Oracle Card)
rat query slice ... --depth 2 --source stdin
        |
        v
canonical route / query / cache / STATE / artifacts
```

`VERIFY STATUS` is deliberately different: it re-reads `/api/completion`, which delegates to the canonical completion gate. It does not execute a new verifier and cannot turn a primitive PASS into a solved challenge.

The Primitive/Finding board and evidence navigation are also read-only projections of `Stream.view()` plus the retained STATE event window. Desktop does not copy or revise finding, primitive, observation, or evidence semantics.

## Target selection

The browser does not provide a binary path or argv.

`AnalysisManager` reads the challenge's validated `run.json`, resolves the single `binary` input (and optional `libc` input), requires a challenge-local basename, resolves symlinks, rejects root escape, and re-hashes the local files against the manifest SHA-256 and size.

After `rat brief` returns, Desktop validates the `rat.brief-card/v1` document and requires its reported `binary_sha256` to match the manifest digest. When the manifest supplies a libc, the returned brief's libc SHA-256 must also match that canonical input. A changed or substituted binary/libc is reported as an analysis error rather than accepted as a result for the canonical run.

Bounded query results are validated as `rat.query-result/v1`. When the canonical query result reports `provenance.binary_sha256`, Desktop requires it to match the manifest binary digest. Every query also re-hashes the local target after execution, so a target changed during analysis is rejected.

Private resolved filesystem paths are never serialized by the Desktop analysis APIs.

## HTTP surface

All control requests require `X-CTF-Rat-Desktop: 1`. Request objects are exact-field contracts: extra path, argv, command, budget, source, depth, or binary fields fail closed.

Read-only status:

```text
GET /api/analysis/status
```

Bounded briefing:

```text
POST /api/analysis/brief
{"mode":"fast"}
```

or:

```json
{"mode":"deep"}
```

Bounded Function Card:

```text
POST /api/analysis/function
{"name":"main"}
```

The function name is trimmed, limited to 256 UTF-8 bytes, rejects control characters, and is passed as one argv element.

Bounded Oracle Card:

```text
POST /api/analysis/oracle
{}
```

The client supplies no target, flags, candidate strings, or solver command.

Bounded backward Slice Card:

```text
POST /api/analysis/slice
{"backward":"0x401000"}
```

`backward` must be one decimal or hexadecimal address in the unsigned 64-bit range. Desktop normalizes it to hexadecimal. The client cannot choose slice depth, source, store, or arbitrary rat arguments.

## FAST

FAST invokes:

```text
rat brief <manifest-binary> --format json --budget-tokens 1500 --fast
```

The process runs through `ratlib.runner` with bounded wall time, CPU time, and output. It is argv-only and never uses a shell.

## DEEP

DEEP invokes:

```text
rat brief <manifest-binary> --format json --budget-tokens 1500
```

This is not a separate Desktop analysis implementation. `rat brief` decides which canonical analysis capabilities are available; unavailable richer dependencies remain canonical capability/diagnostic state.

## Function Card

The Function Card path invokes:

```text
rat query func <manifest-binary> <function-name> \
  --fast --budget-bytes 32768 --format json
```

Desktop renders a bounded projection of canonical facts:

- callers
- callees
- strings
- coverage completeness
- query status and duration

The UI previews at most six items per list. Desktop does not decompile the function and does not create a parallel function-analysis cache.

## Oracle Card

The Oracle path invokes:

```text
rat query oracle <manifest-binary> \
  --fast --budget-bytes 32768 --format json
```

The projection keeps the canonical distinction between facts and heuristics. It displays:

- exact success-candidate count
- exact failure-candidate count
- bounded previews of success/failure candidates
- canonical `auto_connect` decision (`yes` or `withheld`)
- coverage/status/duration

Desktop never turns candidate strings into a success oracle by itself.

## Slice Card

The Slice path invokes:

```text
rat query slice <manifest-binary> \
  --backward <address> --depth 2 --source stdin --format json
```

The UI displays only a bounded projection such as target function/address, input API calls, direct calls, interprocedural depth, status, and coverage. The underlying rat-slice contract explicitly treats the data slice and loop summaries as conservative candidates rather than proof; Desktop preserves that meaning and never promotes them to a primitive or verified finding.

## Primitive / Finding board

`Stream.view()` already materializes canonical `findings`, `primitives`, and `observations`. Desktop renders that existing view directly.

The board:

- displays at most 24 current primitives/findings
- orders stronger/active states ahead of blocked/stale/refuted states for operator scanning
- shows the canonical `status` / `state`; it does not calculate a replacement status
- works against the selected replay snapshot, so historical replay shows historical materialized state

Selecting a finding exposes its canonical `evidence_observation_ids` and `related_findings`. Selecting a primitive exposes canonical `self_evidence`. Selecting an observation exposes its content-addressed `evidence` digests, which can be opened through the existing verified artifact preview path.

## Timeline / evidence navigation

The Timeline has local display filters only:

```text
ALL / VERIFY / FIND / PRIM / EVID / FAIL
```

Filtering does not change STATE, cursor progression, or replay semantics. `EVID` includes observation and evidence-invalidated events; `FAIL` includes failure and alert events.

Inspector backlinks can follow:

- event `caused_by` IDs when the referenced event is still in the bounded local timeline window
- finding/primitive evidence observation IDs in the selected snapshot
- observation artifact digests through canonical artifact preview
- finding `related_findings`

No bookmark DB or secondary evidence graph is introduced.

## VERIFY STATUS

The UI button is intentionally named `VERIFY STATUS`, not `VERIFY`.

It calls the existing canonical completion projection. A green `VERIFIED` result requires the runtime completion gate to authenticate the active non-stale verification lineage. A successful gate response with `verified=false` is displayed as `NOT VERIFIED`; an unavailable request remains error/unknown. Desktop does not fabricate a solve-state conclusion beyond the canonical gate.

A true verifier-execution control still requires a canonical verification-request contract that supplies the profile, trace, scenario, primitive, exploit task, and oracle provenance required by `rat-verify`. v0.3 does not invent a Desktop-only substitute.

## Typed intervention — deferred

Source review found durable low-level orchestration gates (`enter`, `rollback`, phase/task contracts, verification linkage), but no canonical high-level intent request contract equivalent to `investigate-function`, `rule-out-route`, or `return-to-fast` that a Desktop adapter could call without defining new semantics.

Therefore v0.3 does **not** add a Desktop-only typed intervention subsystem. FAST/DEEP and the bounded query cards remain the supported controls. Typed intervention should be reconsidered only after the runtime exposes one canonical validated intent/request interface with deterministic tests.

## Concurrency and budgets

FAST, DEEP, Function, Oracle, and Slice requests share one in-memory execution lock. The lock is only an execution guard; it is not state or evidence and is discarded on daemon restart.

Current adapter budgets:

- FAST wall timeout: 30 seconds
- DEEP wall timeout: 90 seconds
- Function Card wall timeout: 30 seconds
- Oracle wall timeout: 30 seconds
- Slice wall timeout: 90 seconds
- brief child CPU limit: 60 seconds
- Function/Oracle child CPU limit: 30 seconds
- Slice child CPU limit: 60 seconds
- stdout/stderr hard cap: 256 KiB each
- brief context budget: 1,500 tokens
- Function/Oracle fact budget: 32 KiB
- Slice depth/source: fixed at `2` / `stdin`

STATE, artifact, cache, query, and governor side effects are whatever the canonical `rat` implementation records. Desktop does not reproduce them.

## UI

The v0.3 command bar sits above the existing workbench and keeps the workbench information architecture intact. It shows:

- manifest-selected target name and shortened digest
- FAST / DEEP
- bounded FUNC input
- ORACLE
- bounded SLICE address input
- VERIFY STATUS
- bounded cards for the latest requested analysis result

The workbench adds a compact Primitive/Finding board, Timeline filters, and evidence/backlink navigation while retaining the existing STATE replay, terminal, artifact browser, and Inspector.

## Regression contract

Desktop CI runs the dedicated analysis tests together with existing Desktop tests. v0.3 tests cover:

- manifest target resolution and digest re-check
- path traversal rejection
- FAST and DEEP fixed-argv construction
- invalid-mode rejection
- output-size budget
- real local `run.json -> AnalysisManager -> rat brief --fast` integration on an Ubuntu ELF fixture
- post-run brief binary digest binding
- post-run supplied-libc digest binding
- bounded Function Card argv/budget/name validation
- bounded Oracle fixed argv/budget validation
- bounded Slice address parsing and fixed `depth=2` / `source=stdin`
- query provenance digest mismatch rejection
- HTTP rejection of injected `argv`, `binary`, `depth`, or other extra fields

The Desktop workflow watches `bin/rat`, `run_manifest.py`, `runner.py`, `schema.py`, STATE/artifact/completion dependencies, and Desktop adapters so canonical contract changes rerun compatibility checks.

## Release gate

Synthetic Desktop benchmarks, build/package validation, and repository regression are necessary but not sufficient for the v0.3 release decision. Real CTF-session telemetry must still be reconciled before the package version is promoted to `0.3.0` or the draft PR is marked ready for merge.
