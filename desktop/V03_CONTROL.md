# Desktop v0.3 — bounded analysis control

## Status

This v0.3 slice adds bounded control and query surfaces without turning Desktop into a second solver, decompiler, verifier, or generic command runner.

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
rat brief --fast              (FAST)
rat brief                     (DEEP)
rat query func ... --fast     (Function Card)
        |
        v
canonical route / query / cache / STATE / artifacts
```

`VERIFY STATUS` is deliberately different: it re-reads `/api/completion`, which delegates to the canonical completion gate. It does not execute a new verifier and cannot turn a primitive PASS into a solved challenge.

## Target selection

The browser does not provide a binary path or argv.

`AnalysisManager` reads the challenge's validated `run.json`, resolves the single `binary` input (and optional `libc` input), requires a challenge-local basename, resolves symlinks, rejects root escape, and re-hashes the local files against the manifest SHA-256 and size.

After `rat brief` returns, Desktop validates the `rat.brief-card/v1` document and requires its reported `binary_sha256` to match the manifest digest. When the manifest supplies a libc, the returned brief's libc SHA-256 must also match that canonical input. A changed or substituted binary/libc is reported as an analysis error rather than accepted as a result for the canonical run.

Function queries re-hash the target after the bounded query returns and reject the result if the local target changed during analysis.

Private resolved filesystem paths are never serialized by the Desktop analysis APIs.

## HTTP surface

Read-only status:

```text
GET /api/analysis/status
```

Bounded briefing:

```text
POST /api/analysis/brief
X-CTF-Rat-Desktop: 1
Content-Type: application/json

{"mode":"fast"}
```

or:

```json
{"mode":"deep"}
```

The body must contain exactly one field, `mode`, and only `fast` or `deep` are accepted. Requests containing `argv`, `binary`, paths, or additional fields fail closed.

Bounded Function Card query:

```text
POST /api/analysis/function
X-CTF-Rat-Desktop: 1
Content-Type: application/json

{"name":"main"}
```

The body must contain exactly one string field, `name`. The adapter trims surrounding whitespace, limits the name to 256 UTF-8 bytes, rejects control characters, and passes it as one argv element. It never treats the name as shell syntax.

## FAST

FAST invokes the canonical front door as:

```text
rat brief <manifest-binary> --format json --budget-tokens 1500 --fast
```

The process is executed through `ratlib.runner` with bounded wall time, CPU time, and output. The command is argv-only and never uses a shell.

## DEEP

DEEP invokes:

```text
rat brief <manifest-binary> --format json --budget-tokens 1500
```

This is not a separate Desktop analysis implementation. `rat brief` decides which canonical analysis capabilities are available; if a richer dependency is unavailable, the brief contract remains responsible for the resulting capability/diagnostic state.

## Function Card

The Function Card path invokes:

```text
rat query func <manifest-binary> <function-name> \
  --fast --budget-bytes 32768 --format json
```

Desktop validates the returned `rat.query-result/v1` document and renders a bounded projection of the canonical facts:

- callers
- callees
- strings
- coverage completeness
- query status and duration

The UI previews at most six items per list even though the backend query result itself is already budget-bounded. Desktop does not decompile the function and does not create a parallel function-analysis cache.

The query uses `--fast` intentionally. Deeper whole-binary work belongs to DEEP; a Function Card is a targeted, bounded working-set query.

## VERIFY STATUS

The UI button is intentionally named `VERIFY STATUS`, not `VERIFY`.

It calls the existing canonical completion projection. A green `VERIFIED` result therefore still requires the runtime's completion gate to authenticate the active non-stale verification lineage. A successful gate response with `verified=false` is displayed as `NOT VERIFIED`; an unavailable request remains an error/unknown state. Desktop does not fabricate a solve-state conclusion beyond the canonical gate.

A future true verifier-execution control requires a canonical verification-request contract that supplies the profile, trace, scenario, primitive, exploit task, and oracle provenance required by `rat-verify`. v0.3 does not invent a Desktop-only substitute for those inputs.

## Concurrency and budgets

Desktop serializes FAST, DEEP, and Function Card requests with one in-memory lock. The lock is only an execution guard; it is not state or evidence and is discarded on daemon restart.

Current adapter budgets:

- FAST wall timeout: 30 seconds
- DEEP wall timeout: 90 seconds
- Function Card wall timeout: 30 seconds
- brief child CPU limit: 60 seconds
- Function Card child CPU limit: 30 seconds
- stdout/stderr hard cap: 256 KiB each
- brief context budget: 1,500 tokens
- Function Card fact budget: 32 KiB

STATE, artifact, cache, query, and governor side effects are whatever the canonical `rat` implementation records. Desktop does not reproduce them.

## UI

The v0.3 command bar sits above the existing workbench and keeps the v0.2 information architecture intact. It shows:

- manifest-selected target name and shortened digest
- FAST / DEEP controls
- bounded function-name input + FUNC action
- VERIFY STATUS
- latest route/subroute, confidence, duration, and next bounded query when available
- compact Function Card facts for callers/callees/strings
- bounded error status

The main STATE timeline, terminal, artifact browser, replay, and inspector remain unchanged.

## Regression contract

Desktop CI runs the dedicated analysis tests together with existing Desktop tests. The v0.3 tests cover:

- manifest target resolution and digest re-check
- path traversal rejection
- FAST and DEEP fixed-argv construction
- invalid-mode rejection
- output-size budget
- real local `run.json -> AnalysisManager -> rat brief --fast` integration on an Ubuntu ELF fixture
- post-run brief binary digest binding
- post-run supplied-libc digest binding
- bounded Function Card argv/budget/name validation
- HTTP rejection of injected `argv` or `binary` fields for both briefing and function queries

The Desktop workflow also watches the canonical dependencies used by this adapter: `bin/rat`, `run_manifest.py`, `runner.py`, and `schema.py`, in addition to the existing STATE/artifact/completion dependencies.
