# CTF-Rat Desktop

Desktop workbench for the CTF-Rat v2 runtime.

The desktop layer is intentionally **not** a second solver implementation. `rat`, STATE v2, artifacts/cache, verification, and orchestration remain canonical. Desktop adds a loopback-only control/observation plane (`ratd`) plus a Tauri/React UI for watching and controlling one explicitly configured local solver process.

## v0.2 workbench

- Tauri 2 shell + React/TypeScript UI
- live Activity Timeline from append-only STATE v2
- materialized current/historical STATE view
- replay slider: inspect what the solver knew at event `#N`
- serialized polling and latest-request-wins replay updates
- opaque generation-token fast path for unchanged STATE polling
- automatic workbench reset when the canonical STATE stream ID changes
- single-parse live snapshot projection; historical replay keeps the conservative canonical path
- bounded PTY session manager with process-group shutdown
- Start/Stop controls for one daemon-configured solver command
- live terminal output + bounded terminal input
- session-safe terminal cursors across solver and `ratd` restarts
- failed solver spawn preserves the previous terminal log/cursor generation
- artifact browser backed by the existing content-addressed store
- text/JSON artifact preview and bounded base64 preview for binary artifacts
- event telemetry API without duplicate telemetry polling in the UI
- loopback-only HTTP API with restricted browser origins
- POST controls require `X-CTF-Rat-Desktop: 1`
- locked npm/Cargo dependency resolution
- CI-built Linux `.deb` and AppImage bundles
- no second state DB, cache, solver, or verification path

## Architecture

```text
Tauri / React Workbench
        |
        | loopback HTTP
        v
      ratd
     / |  \
    /  |   \
 PTY  STATE  artifact store
  |     |       |
configured     existing
solver cmd     CTF-Rat truth
```

`ratd` never accepts arbitrary argv from HTTP. The operator configures a solver command once at daemon startup; the UI can only start/stop that command and send PTY input to the running process.

## Run from source

Install the locked frontend dependencies:

```bash
cd desktop
npm ci
cd ..
```

### Observer mode

Watch an already-running CTF-Rat session:

```bash
python3 bin/ratd --challenge /path/to/challenge
cd desktop && npm run tauri dev
```

### Controlled solver mode

Configure the exact local solver/agent command when starting `ratd`:

```bash
python3 bin/ratd \
  --challenge /path/to/challenge \
  --solver-command "<your existing local CTF-Rat agent command>"
```

Then open the app:

```bash
cd desktop
npm run tauri dev
```

The browser/UI does not choose or alter the argv. `--solver-command` is parsed with `shlex.split()` and executed directly without a shell.

### Development launcher

```bash
chmod +x desktop/dev.sh
./desktop/dev.sh /path/to/challenge
```

With a configured solver command:

```bash
./desktop/dev.sh /path/to/challenge "<your existing local CTF-Rat agent command>"
```

`ratd` listens on `127.0.0.1:8765` by default. In browser/Vite development, `VITE_RATD_URL` may point the frontend at another explicitly chosen loopback `ratd` port. Packaged Tauri v0.2 builds are intentionally narrower: the committed CSP permits only `http://127.0.0.1:8765` and `http://localhost:8765`. A packaged custom endpoint therefore requires a corresponding `app.security.csp` `connect-src` change at build time while preserving the loopback-only policy.

## Linux packages

Build the same bundle targets used by CI:

```bash
cd desktop
npm ci
npm run tauri -- build --bundles deb,appimage
```

Outputs are written below:

```text
desktop/src-tauri/target/release/bundle/deb/
desktop/src-tauri/target/release/bundle/appimage/
```

The `desktop-workbench` GitHub Actions workflow uploads both bundle types as a `ctf-rat-desktop-linux-<sha>` artifact on pull-request validation runs.

The installer contains the Tauri workbench, not a second copy of the CTF-Rat solver runtime. `ratd` and the existing repository/runtime remain the canonical backend and must be available separately.

## API

Read-only projections:

```text
GET /api/health
GET /api/snapshot
GET /api/snapshot?until_seq=<n>
GET /api/events?after_seq=<n>&limit=<n>
GET /api/telemetry
GET /api/session
GET /api/terminal?after=<cursor>&limit=<n>
GET /api/artifacts?limit=<n>
GET /api/artifacts/<sha256:digest>?max_bytes=<n>
```

`/api/events` returns an event cursor containing `stream_id`, `seq`, and, after a stable validated read, an opaque `source_generation` string. The workbench echoes that generation as `known_generation` on its next poll. If the append-only STATE file is unchanged, `ratd` can answer without reparsing JSONL. Any generation mismatch falls back to canonical `Stream.read()` validation. Clients must treat the generation as opaque; it intentionally encodes filesystem timing data as a string because nanosecond timestamps exceed JavaScript's safe integer range.

If the canonical STATE `stream_id` changes, `/api/events` returns `reset: true` and restarts the sequence cursor from zero. The workbench then resets timeline/replay/terminal presentation and reloads the current snapshot/artifacts rather than mixing two runs.

The terminal `cursor` is an opaque, monotonically increasing value returned by the previous `/api/terminal` response. Clients must pass that returned value back as `after`; it is not a raw byte offset. Cursor generation is persisted in the existing `.rat/desktop/session.json`, so a cursor from an older solver session or a restarted `ratd` safely maps to the beginning of the current truncated terminal log rather than skipping its prefix.

Bounded controls:

```text
POST /api/session/start
POST /api/session/stop
POST /api/session/input    {"data":"..."}
```

POST requests must include:

```text
X-CTF-Rat-Desktop: 1
Content-Type: application/json
```

The daemon only accepts loopback bind addresses and only permits the development/Tauri origins declared in `bin/ratd`.

## Polling benchmark

The repository contains a deterministic, non-gating microbenchmark for the read-only Desktop projections:

```bash
python3 tests/bench_desktop_polling.py --events 100,1000,5000 --iterations 7
```

It writes a valid synthetic STATE v2 JSONL fixture directly, warms the filesystem cache, and records wall-clock and process-CPU p50/p95/max. CI runs a shorter three-iteration sample and uploads the JSONL result as `ctf-rat-desktop-poll-benchmark-<sha>`. These numbers are evidence for ablation comparisons, not fixed performance thresholds; absolute values vary with runner load.

GitHub Actions run `32657156715` on source commit `4fb12d406f800c4ae9e11efedc97399d582c44b3` measured:

| STATE events | idle full scan p50 | unchanged fast path p50 | fast-path ratio | live snapshot p50 | UI changed-refresh estimate p50 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 0.572 ms | 0.016 ms | 35.75x | 0.640 ms | 1.214 ms |
| 1,000 | 9.872 ms | 0.023 ms | 429.22x | 5.898 ms | 15.659 ms |
| 5,000 | 28.762 ms | 0.013 ms | 2,212.46x | 29.862 ms | 57.606 ms |

The live snapshot path uses the canonical `Stream.view()` materializer once, then derives only cursor/count from the same stable validated JSONL generation. It does not introduce a second STATE model. Historical replay remains on the conservative full canonical path because it is interactive rather than part of the 500 ms live polling loop. The workbench also no longer requests `/api/telemetry` on every state change because `Snapshot.total_event_count` already supplies the only telemetry value displayed by the UI; the telemetry endpoint remains available for external inspection.

## Test

Desktop backend and end-to-end tests:

```bash
python3 -m unittest \
  tests.test_desktop_api \
  tests.test_desktop_session \
  tests.test_desktop_http \
  tests.test_desktop_e2e
```

The E2E smoke test runs a configured local solver fixture through the same session manager and HTTP handler, then verifies PTY terminal output, STATE v2 live projection, historical replay, and the canonical artifact store. Session tests additionally verify rapid solver restart, failed-spawn preservation, and stale terminal cursor recovery across a reconstructed `SessionManager`, modeling a `ratd` restart. API/HTTP tests verify stream-reset behavior, opaque generation round-tripping, and that unchanged generation polling does not call `Stream.read()`.

All repository Python tests still include these through normal discovery:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Frontend build check:

```bash
cd desktop
npm ci
npm run build
```

Tauri compile check:

```bash
cargo check --locked --manifest-path desktop/src-tauri/Cargo.toml
```

The desktop CI also verifies that `package-lock.json` and `Cargo.lock` remain unchanged by the build.

## Current boundaries

- Linux is the canonical solver runtime because CTF-Rat depends on ELF/GDB/angr/pwntools/Ghidra tooling.
- Windows desktop use should host the solver runtime in WSL2; macOS should use the existing Linux VM/container path where required.
- Desktop does not submit flags, mutate evidence directly, create findings, or bypass `rat`/verification gates.
- Arbitrary command execution is not exposed through the HTTP API.
- Linux installer bundles package the UI shell only; they do not make the Linux CTF-Rat analysis runtime cross-platform.

## Verified release gates

The desktop branch CI verifies:

1. desktop API/session/HTTP/E2E tests,
2. Python syntax checks for daemon modules and the polling benchmark,
3. reproducible polling benchmark artifact generation,
4. `npm ci` against the committed lockfile,
5. TypeScript/Vite production build,
6. `cargo check --locked`,
7. `.deb` and AppImage bundle generation on PR validation runs,
8. Debian metadata and AppImage internal executable validation,
9. unchanged npm/Cargo lockfiles after the build,
10. upload of both installer artifacts.
