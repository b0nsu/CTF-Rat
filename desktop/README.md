# CTF-Rat Desktop

Desktop workbench for the CTF-Rat v2 runtime.

The desktop layer is intentionally **not** a second solver implementation. `rat`, STATE v2, artifacts/cache, verification, and orchestration remain canonical. Desktop adds a loopback-only control/observation plane (`ratd`) plus a Tauri/React UI for watching and controlling one explicitly configured local solver process.

## v0.2 workbench

- Tauri 2 shell + React/TypeScript UI
- live Activity Timeline from append-only STATE v2
- materialized current/historical STATE view
- replay slider: inspect what the solver knew at event `#N`
- serialized polling and latest-request-wins replay updates
- bounded PTY session manager with process-group shutdown
- Start/Stop controls for one daemon-configured solver command
- live terminal output + bounded terminal input
- session-safe terminal cursors across solver and `ratd` restarts
- artifact browser backed by the existing content-addressed store
- text/JSON artifact preview and bounded base64 preview for binary artifacts
- event telemetry and session status
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

`ratd` listens on `127.0.0.1:8765` by default. The frontend endpoint can be supplied at build/dev time with `VITE_RATD_URL`; packaged v0.2 builds use the default loopback endpoint unless rebuilt with another allowed endpoint.

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

## Test

Desktop backend and end-to-end tests:

```bash
python3 -m unittest \
  tests.test_desktop_api \
  tests.test_desktop_session \
  tests.test_desktop_http \
  tests.test_desktop_e2e
```

The E2E smoke test runs a configured local solver fixture through the same session manager and HTTP handler, then verifies PTY terminal output, STATE v2 live projection, historical replay, and the canonical artifact store. Session tests additionally verify rapid solver restart and stale terminal cursor recovery across a reconstructed `SessionManager`, modeling a `ratd` restart.

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
2. Python syntax checks for daemon modules,
3. `npm ci` against the committed lockfile,
4. TypeScript/Vite production build,
5. `cargo check --locked`,
6. `.deb` and AppImage bundle generation on PR validation runs,
7. Debian metadata and AppImage internal executable validation,
8. unchanged npm/Cargo lockfiles after the build,
9. upload of both installer artifacts.
