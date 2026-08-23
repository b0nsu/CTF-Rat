# CTF-Rat Desktop

Desktop workbench for the CTF-Rat v2 runtime.

The desktop layer is intentionally **not** a second solver implementation. `rat`, STATE v2, artifacts/cache, verification, and orchestration remain canonical. Desktop adds a loopback-only control/observation plane (`ratd`) plus a Tauri/React UI for watching and controlling one explicitly configured local solver process.

## v0.2 workbench

- Tauri 2 shell + React/TypeScript UI
- live Activity Timeline from append-only STATE v2
- materialized current/historical STATE view
- replay slider: inspect what the solver knew at event `#N`
- bounded PTY session manager with process-group shutdown
- Start/Stop controls for one daemon-configured solver command
- live terminal output + bounded terminal input
- artifact browser backed by the existing content-addressed store
- text/JSON artifact preview and bounded base64 preview for binary artifacts
- event telemetry and session status
- loopback-only HTTP API with restricted browser origins
- POST controls require `X-CTF-Rat-Desktop: 1`
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

## Run

Install frontend dependencies once:

```bash
cd desktop
npm install
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

`ratd` listens on `127.0.0.1:8765` by default. Override only the frontend endpoint when needed:

```bash
VITE_RATD_URL=http://127.0.0.1:8765 npm run tauri dev
```

## API

Read-only projections:

```text
GET /api/health
GET /api/snapshot
GET /api/snapshot?until_seq=<n>
GET /api/events?after_seq=<n>&limit=<n>
GET /api/telemetry
GET /api/session
GET /api/terminal?after=<byte-offset>&limit=<n>
GET /api/artifacts?limit=<n>
GET /api/artifacts/<sha256:digest>?max_bytes=<n>
```

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

Backend desktop tests:

```bash
python3 -m unittest tests.test_desktop_api tests.test_desktop_session
```

All repository Python tests still include these through normal discovery:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Frontend build check:

```bash
cd desktop
npm install
npm run build
```

Tauri compile check:

```bash
cargo check --manifest-path desktop/src-tauri/Cargo.toml
```

The `desktop` GitHub Actions workflow performs the backend tests, frontend build, and Rust compile check on pushes to the branch and on desktop-related pull-request changes.

## Current boundaries

- Linux is the canonical solver runtime because CTF-Rat depends on ELF/GDB/angr/pwntools/Ghidra tooling.
- Windows desktop use should host the solver runtime in WSL2; macOS should use the existing Linux VM/container path where required.
- Desktop does not submit flags, mutate evidence directly, create findings, or bypass `rat`/verification gates.
- Arbitrary command execution is not exposed through the HTTP API.
- Bundle/installers are intentionally not enabled until CI proves the frontend and Tauri crate are stable on the desktop branch.

## Next release gate

Enable packaged installers only after:

1. desktop backend tests pass in CI,
2. `npm run build` passes,
3. `cargo check` passes with Tauri system dependencies,
4. session restart/stop tests are stable,
5. a local CTF fixture is replayed end-to-end without changing canonical STATE semantics.
