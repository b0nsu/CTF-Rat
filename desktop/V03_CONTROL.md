# Desktop v0.3 — bounded analysis control

## Status

This is the first v0.3 slice. It adds a bounded control surface without turning Desktop into a second solver or a generic command runner.

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
rat brief --fast    (FAST)
rat brief           (DEEP)
        |
        v
canonical route / cache / STATE / artifacts
```

`VERIFY STATUS` is deliberately different: it re-reads `/api/completion`, which delegates to the canonical completion gate. It does not execute a new verifier and cannot turn a primitive PASS into a solved challenge.

## Target selection

The browser does not provide a binary path or argv.

`AnalysisManager` reads the challenge's validated `run.json`, resolves the single `binary` input (and optional `libc` input), requires a challenge-local basename, resolves symlinks, rejects root escape, and re-hashes the local file against the manifest SHA-256 and size.

After `rat brief` returns, Desktop validates the `rat.brief-card/v1` document and requires its reported `binary_sha256` to match the manifest digest. This closes the adapter's pre-run/post-run identity check; a changed target is reported as an analysis error rather than accepted as a result for the canonical run.

Private resolved filesystem paths are never serialized by `/api/analysis/status` or `/api/analysis/brief`.

## HTTP surface

Read-only status:

```text
GET /api/analysis/status
```

Bounded analysis:

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

## VERIFY STATUS

The UI button is intentionally named `VERIFY STATUS`, not `VERIFY`.

It calls the existing canonical completion projection. A green `VERIFIED` result therefore still requires the runtime's completion gate to authenticate the active non-stale verification lineage. An unavailable request remains an error/unknown state; Desktop does not fabricate `OPEN` or `VERIFIED`.

A future true verifier-execution control requires a canonical verification-request contract that supplies the profile, trace, scenario, primitive, exploit task, and oracle provenance required by `rat-verify`. v0.3 does not invent a Desktop-only substitute for those inputs.

## Concurrency and budgets

Desktop serializes FAST/DEEP requests with one in-memory lock. The lock is only an execution guard; it is not state or evidence and is discarded on daemon restart.

Current adapter budgets:

- FAST wall timeout: 30 seconds
- DEEP wall timeout: 90 seconds
- child CPU limit: 60 seconds
- stdout/stderr hard cap: 256 KiB each
- brief context budget: 1,500 tokens

STATE, artifact, cache, and governor side effects are whatever the canonical `rat brief` implementation records. Desktop does not reproduce them.

## UI

The v0.3 command bar sits above the existing workbench and keeps the v0.2 information architecture intact. It shows:

- manifest-selected target name and shortened digest
- FAST / DEEP controls
- VERIFY STATUS
- latest route/subroute, confidence, duration, and next bounded query when available
- bounded error status

The main STATE timeline, terminal, artifact browser, replay, and inspector remain unchanged.

## Regression contract

Desktop CI runs the dedicated analysis tests together with existing Desktop tests. The v0.3 tests cover:

- manifest target resolution and digest re-check
- path traversal rejection
- FAST and DEEP fixed-argv construction
- invalid-mode rejection
- output-size budget
- post-run brief digest binding
- HTTP rejection of injected `argv` or `binary` fields

The Desktop workflow also watches the canonical dependencies used by this adapter: `bin/rat`, `run_manifest.py`, `runner.py`, and `schema.py`, in addition to the existing STATE/artifact/completion dependencies.
