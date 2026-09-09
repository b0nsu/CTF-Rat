# CTF-Rat Desktop

Desktop workbench for the CTF-Rat v2 runtime.

The Desktop layer is intentionally **not** a second solver implementation. `rat`, STATE v2, artifacts/cache, orchestration, verification, completion, and metrics remain canonical. Desktop adds a loopback-only control/observation plane (`ratd`) plus a Tauri/React UI for observing and issuing bounded requests to that runtime.

The branch currently contains the **v0.3 development preview**. Package metadata remains `0.2.0` until real-session telemetry is reconciled and the v0.3 release gate is accepted.

## v0.3 preview workbench

### Observe

- live Activity Timeline from append-only STATE v2
- materialized current/historical STATE view
- replay slider for event `#N`
- combined `/api/live` changed-state delta + snapshot projection
- opaque generation fast path for unchanged STATE polling
- stream reset handling without mixing event histories
- current primitive/finding/failure focus strip
- Primitive/Finding board projected directly from canonical `Stream.view()`
- Timeline filters for verification, findings, primitives, evidence, and failures
- evidence navigation: finding/primitive -> observation -> content-addressed artifact
- event `caused_by` backlinks within the bounded retained Timeline window
- canonical completion-gate status (`VERIFIED`, `NOT VERIFIED`, or unavailable)
- bounded session metrics without adding telemetry to the 500 ms idle hot path

### Control / query

- one daemon-configured local solver command with Start/Stop and bounded PTY input
- FAST -> canonical `rat brief --fast`
- DEEP -> canonical `rat brief`
- FUNC -> canonical bounded `rat query func --fast`
- ORACLE -> canonical bounded `rat query oracle --fast`
- SLICE -> canonical `rat query slice` with Desktop-fixed `depth=2`, `source=stdin`
- VERIFY STATUS -> reads the canonical completion gate; it does not execute or replace `rat-verify`

The browser cannot supply an analysis binary path, libc path, arbitrary argv, command, shell fragment, query budget, slice depth, or slice source. Analysis targets come from validated `rat.run/v1` `run.json` inputs and are SHA-256/size checked before use. Results remain bound to the canonical binary identity after execution.

See [`V03_CONTROL.md`](./V03_CONTROL.md) for the exact bounded-control contract and [`DESIGN.md`](./DESIGN.md) for the workbench UI contract.

## Architecture

```text
Tauri / React Workbench
        |
        | loopback HTTP
        v
      ratd
    /  |   \
   /   |    \
 PTY  rat   read projections
  |    |      |
configured  STATE v2 / artifacts /
solver cmd  completion / metrics
```

Desktop does not own solver, STATE, cache, evidence, finding, primitive, verification, or orchestration semantics.

## Run from source

Install locked frontend dependencies:

```bash
cd desktop
npm ci
cd ..
```

### Observer mode

```bash
python3 bin/ratd --challenge /path/to/challenge
cd desktop && npm run tauri dev
```

### Controlled solver mode

Configure one exact local solver/agent command when starting `ratd`:

```bash
python3 bin/ratd \
  --challenge /path/to/challenge \
  --solver-command "<your existing local CTF-Rat agent command>"
```

Then:

```bash
cd desktop
npm run tauri dev
```

`--solver-command` is parsed with `shlex.split()` and executed directly without a shell. HTTP clients cannot alter the configured argv.

### Development launcher

```bash
chmod +x desktop/dev.sh
./desktop/dev.sh /path/to/challenge
```

With a configured solver command:

```bash
./desktop/dev.sh /path/to/challenge "<your existing local CTF-Rat agent command>"
```

`ratd` listens on `127.0.0.1:8765` by default. Browser/Vite development may use `VITE_RATD_URL` for another explicitly selected loopback endpoint. Packaged Tauri builds retain a narrower committed CSP and permit the default loopback endpoint.

## Linux packages

Build the same targets used by CI:

```bash
cd desktop
npm ci
npm run tauri -- build --bundles deb,appimage
```

Outputs:

```text
desktop/src-tauri/target/release/bundle/deb/
desktop/src-tauri/target/release/bundle/appimage/
```

The installer contains the Tauri workbench, not a second copy of the CTF-Rat solver runtime. `ratd` and the existing repository/runtime remain the canonical backend.

## API

### Read projections

```text
GET /api/health
GET /api/analysis/status
GET /api/live?after_seq=<n>&limit=<n>&stream_id=<id>&known_generation=<opaque>
GET /api/snapshot
GET /api/snapshot?until_seq=<n>
GET /api/events?after_seq=<n>&limit=<n>
GET /api/telemetry
GET /api/completion
GET /api/session
GET /api/terminal?after=<cursor>&limit=<n>
GET /api/artifacts?limit=<n>&known_generation=<opaque>
GET /api/artifacts/<sha256:digest>?max_bytes=<n>
```

### Bounded controls

All POST controls require:

```text
X-CTF-Rat-Desktop: 1
Content-Type: application/json
```

```text
POST /api/session/start        {}
POST /api/session/stop         {}
POST /api/session/input        {"data":"..."}

POST /api/analysis/brief       {"mode":"fast"|"deep"}
POST /api/analysis/function    {"name":"main"}
POST /api/analysis/oracle      {}
POST /api/analysis/slice       {"backward":"0x401000"}
```

Each analysis endpoint accepts an exact bounded request shape. Extra `argv`, `binary`, `command`, `depth`, `source`, or other fields fail closed.

## STATE polling contract

The workbench uses `/api/live` for the hot path. On a changed STATE generation, `ratd` performs one canonical `Stream.read()` validation, derives the event delta, and feeds shallow payload facades of those validated events through the existing `Stream.view()` materializer. Desktop does not own STATE materialization semantics.

A generation token is issued only when a stable response is fully caught up (`has_more=false`). Echoing that token permits an unchanged poll to return without reparsing JSONL. A paginated response deliberately withholds it so unread pages cannot be skipped.

Historical replay uses `/api/snapshot?until_seq=` and the board/Inspector render the selected historical materialized view rather than a separate state model.

## Artifact discovery vs verification

Artifact listing and byte consumption intentionally have different contracts:

- discovery validates metadata schema/digest, object presence, and recorded size without hashing every object
- the inventory generation is only an opaque performance hint, never integrity evidence
- preview/get/verify paths retain content SHA-256 verification
- Desktop preview verifies the whole immutable object while retaining only the requested bounded prefix

## Analysis/query contract

FAST/DEEP/FUNC/ORACLE/SLICE are thin adapters over the existing `rat` front door. They share one in-memory execution lock and bounded wall/CPU/output budgets.

Current bounds are documented in [`V03_CONTROL.md`](./V03_CONTROL.md). Important invariants:

- target comes only from canonical `run.json`
- target path must resolve inside the challenge root
- binary/libc inputs are hash/size verified before briefing
- brief output binary/libc identity must match canonical inputs
- bounded query results are schema validated and the binary is re-hashed after execution
- the query result's binary provenance, when present, must match the manifest digest
- no shell execution
- no Desktop-specific decompiler/cache/oracle/verification engine

## Primitive/Finding and evidence navigation

The board renders current `findings` and `primitives` from `Stream.view()` only. It does not write STATE or calculate replacement lifecycle states.

Relations shown by the Inspector are references already present in canonical data:

```text
finding.evidence_observation_ids
primitive.self_evidence
observation.evidence            -> artifact digests
finding.related_findings
event.caused_by
```

Evidence artifacts open through the existing verified artifact-preview path.

## Typed intervention boundary

Desktop does not expose a new `investigate`, `rule-out`, `phase`, or generic solver-intent API. The runtime currently has durable low-level orchestration gates, but no single high-level validated intent request contract for Desktop to adapt without inventing semantics.

Until such a canonical interface exists, v0.3 keeps FAST/DEEP and bounded query cards as the supported analysis controls.

## Measurement harnesses

Synthetic benchmarks are deterministic, non-gating evidence. Absolute values depend on runner load.

```bash
python3 tests/bench_desktop_polling.py --events 100,1000,5000 --iterations 7
python3 tests/bench_desktop_artifacts.py --artifacts 10,100,500 --object-bytes 65536 --iterations 7
```

CI uploads both JSONL results as `ctf-rat-desktop-benchmarks-<sha>`.

The optimizations under measurement are:

- unchanged STATE generation fast path
- combined changed `/api/live` delta+snapshot path
- metadata-only artifact discovery
- unchanged artifact-inventory generation path
- one-object streaming verified preview

The v0.3 query controls are explicit user actions and are not injected into the 500 ms idle polling loop.

## Test

Backend/Desktop integration tests:

```bash
python3 -m unittest \
  tests.test_artifact_describe \
  tests.test_desktop_analysis \
  tests.test_desktop_api \
  tests.test_desktop_session \
  tests.test_desktop_http \
  tests.test_desktop_e2e
```

`tests.test_desktop_analysis` includes a real local Ubuntu ELF integration path:

```text
local /bin/true fixture
-> challenge run.json
-> AnalysisManager
-> canonical rat brief --fast
-> validated rat.brief-card/v1
```

Full Python regression:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Frontend/Tauri checks:

```bash
cd desktop
npm ci
npm run build
cd ..
cargo check --locked --manifest-path desktop/src-tauri/Cargo.toml
```

CI also builds/validates `.deb` + AppImage bundles and verifies npm/Cargo lockfiles remain unchanged.

## Current boundaries

- Linux remains the canonical solver runtime because the analysis stack depends on ELF/GDB/angr/pwntools/Ghidra tooling.
- Windows Desktop deployments should keep the solver runtime in WSL2; macOS should use the existing Linux VM/container path where required.
- Desktop does not submit flags, promote evidence, create/revise findings or primitives, or bypass `rat`/verification gates.
- Arbitrary command execution is not exposed through the HTTP API.
- The Linux installer packages the UI shell only; it does not make the Linux CTF-Rat runtime cross-platform.

## v0.3 release gate

The implementation is not considered a final `0.3.0` release solely because synthetic CI is green. Before version promotion / PR ready / merge, reconcile real CTF-session telemetry against the agreed baseline, especially:

- verified solve / false VERIFIED
- time to first hypothesis / valid primitive / verified solve / flag
- tool calls and duplicate tool calls
- cache requests/hits
- functions decompiled
- STATE/artifact growth
- ratd CPU/RSS and terminal growth
- missed/reset event anomalies
- FAST/DEEP/FUNC/ORACLE/SLICE frequency and latency

Until that evidence is available, keep package metadata at `0.2.0` and PR #13 in draft.
