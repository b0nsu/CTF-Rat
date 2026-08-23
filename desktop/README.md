# CTF-Rat Desktop

Desktop workbench for the CTF-Rat v2 runtime.

The desktop layer is intentionally **not** a second solver implementation. `rat`, STATE v2, artifacts/cache, verification, and orchestration remain canonical. Desktop adds a loopback-only control/observation plane (`ratd`) plus a Tauri/React UI for watching and controlling one explicitly configured local solver process.

## v0.2 workbench

- Tauri 2 shell + React/TypeScript UI
- live Activity Timeline from append-only STATE v2
- materialized current/historical STATE view
- live solver focus strip for the latest recorded next probe plus current primitive/finding status counts
- replay slider: inspect what the solver knew at event `#N`
- serialized polling and latest-request-wins replay updates
- combined `/api/live` projection: changed STATE delta + current snapshot from one validated JSONL read
- opaque generation-token fast path for unchanged STATE polling
- generation tokens are issued only at fully caught-up cursors, never while `has_more=true`
- automatic workbench reset when the canonical STATE stream ID changes
- historical replay keeps the conservative canonical path
- bounded PTY session manager with process-group shutdown
- Start/Stop controls for one daemon-configured solver command
- live terminal output + bounded terminal input
- session-safe terminal cursors across solver and `ratd` restarts
- failed solver spawn preserves the previous terminal log/cursor generation
- artifact browser backed by the existing content-addressed store
- artifact discovery validates metadata/object presence/size without hashing every object
- artifact inventory generation fast path skips unchanged metadata reloads
- text/JSON artifact preview and bounded base64 preview for binary artifacts
- artifact preview uses the canonical store's single-pass streaming verifier and retains only the requested bounded prefix
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
GET /api/live?after_seq=<n>&limit=<n>&stream_id=<id>&known_generation=<opaque>
GET /api/snapshot
GET /api/snapshot?until_seq=<n>
GET /api/events?after_seq=<n>&limit=<n>
GET /api/telemetry
GET /api/session
GET /api/terminal?after=<cursor>&limit=<n>
GET /api/artifacts?limit=<n>&known_generation=<opaque>
GET /api/artifacts/<sha256:digest>?max_bytes=<n>
```

The workbench uses `/api/live` for the hot path. On a changed STATE generation, `ratd` performs one canonical `Stream.read()` validation, derives the bounded event delta, and feeds shallow payload facades of those already-validated events through the existing `Stream.view()` materializer. The adapter does not own STATE semantics and cannot replace canonical validation. Historical replay continues to use `/api/snapshot?until_seq=`.

`/api/live` and compatibility `/api/events` return an event cursor containing `stream_id`, `seq`, and, only when the cursor has consumed the complete stable generation, an opaque `source_generation` string. The client echoes that value as `known_generation`. If the append-only STATE file is unchanged, `ratd` can answer without reparsing JSONL. A paginated response with `has_more=true` deliberately omits `source_generation`; otherwise a client could skip unread pages by taking the unchanged fast path too early.

If the canonical STATE `stream_id` changes, the delta returns `reset: true` and restarts the sequence cursor from zero. The workbench resets timeline/replay/terminal presentation rather than mixing two streams.

The terminal `cursor` is an opaque, monotonically increasing value returned by the previous `/api/terminal` response. Clients must pass that returned value back as `after`; it is not a raw byte offset. Cursor generation is persisted in the existing `.rat/desktop/session.json`, so a cursor from an older solver session or a restarted `ratd` safely maps to the beginning of the current truncated terminal log rather than skipping its prefix.

### Artifact discovery vs verification

Artifact listing and artifact byte consumption intentionally have different contracts:

- `artifact.describe()` / `/api/artifacts` validate immutable metadata schema/digest, object existence, and recorded object size. They do **not** claim that object bytes were SHA-256 verified.
- `/api/artifacts` returns an opaque metadata-inventory `generation`. If the same generation is echoed back, the daemon can return `unchanged: true` without reopening/parsing every metadata document.
- `artifact.metadata()`, `artifact.preview()`, `artifact.get()`, and `artifact.verify()` retain content-integrity verification.
- Desktop preview hashes the complete immutable object once while retaining only the requested `max_bytes` prefix in memory. `total_bytes` is the verified object size.

The artifact inventory generation is only a performance hint over an immutable metadata tree; it is not evidence and does not weaken byte-consuming verification paths.

## Measurement harnesses

The benchmarks are deterministic, non-gating evidence for ablation decisions. Absolute values depend on runner load.

### STATE polling

```bash
python3 tests/bench_desktop_polling.py --events 100,1000,5000 --iterations 7
```

GitHub Actions run `32674768350` on source commit `61d9055e0e35afc15b7bf665a282bfe50309be59` measured:

| STATE events | unchanged live p50 | legacy changed refresh p50 | combined changed refresh p50 | changed speedup |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 0.012 ms | 1.114 ms | 0.621 ms | 1.79x |
| 1,000 | 0.011 ms | 10.062 ms | 5.234 ms | 1.92x |
| 5,000 | 0.011 ms | 56.019 ms | 28.459 ms | 1.97x |

The first combined implementation deep-copied all events and benchmarked slower than the legacy sequence, so it was not accepted as-is. The retained implementation instead gives `Stream.view()` minimal event facades with shallow payload copies; tests prove that projection-side status changes do not mutate the delta payloads.

### Artifact discovery

```bash
python3 tests/bench_desktop_artifacts.py --artifacts 10,100,500 --object-bytes 65536 --iterations 7
```

The same CI run measured:

| Artifacts | Total object bytes | full listing p50 | unchanged inventory p50 | speedup | one preview p50 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 640 KiB | 0.584 ms | 0.169 ms | 3.46x | 0.226 ms |
| 100 | 6.25 MiB | 5.014 ms | 1.370 ms | 3.66x | 0.291 ms |
| 500 | 31.25 MiB | 22.860 ms | 4.775 ms | 4.79x | 0.219 ms |

Listing cost is now metadata/inventory work rather than hashing every object. Preview cost for this fixture remains nearly independent of artifact count because it verifies one selected object.

CI uploads both JSONL files together as `ctf-rat-desktop-benchmarks-<sha>`.

## Test

Desktop backend and end-to-end tests:

```bash
python3 -m unittest \
  tests.test_artifact_describe \
  tests.test_desktop_api \
  tests.test_desktop_session \
  tests.test_desktop_http \
  tests.test_desktop_e2e
```

The E2E smoke test runs a configured local solver fixture through the same session manager and HTTP handler, then verifies PTY terminal output, the combined live STATE projection, unchanged generation round-tripping, historical replay, and the canonical artifact store. API/HTTP tests also lock the caught-up-only STATE generation invariant and artifact-inventory generation behavior.

All repository Python tests include these through normal discovery:

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

1. artifact/desktop API/session/HTTP/E2E tests,
2. Python syntax checks for daemon modules and both benchmark harnesses,
3. reproducible STATE polling and artifact-discovery benchmark artifacts,
4. `npm ci` against the committed lockfile,
5. TypeScript/Vite production build,
6. `cargo check --locked`,
7. `.deb` and AppImage bundle generation on PR validation runs,
8. Debian metadata and AppImage internal executable validation,
9. unchanged npm/Cargo lockfiles after the build,
10. upload of both installer artifacts.
