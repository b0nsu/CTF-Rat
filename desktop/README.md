# CTF-Rat Desktop

Experimental desktop observer for the CTF-Rat v2 runtime.

The desktop layer is intentionally **not** a second solver implementation. It reads the existing STATE v2 event stream through `ratd`, renders the solver timeline, and keeps `rat`, artifacts, cache, verification, and orchestration as the canonical runtime.

## Current MVP

- Tauri 2 shell + React/TypeScript UI
- live Activity Timeline from STATE v2
- materialized STATE counters
- event inspector with raw typed payload
- loopback-only, read-only `ratd` HTTP API
- bounded event delta API (no second state database)

## Run

From the repository root, point the observer at an existing challenge directory:

```bash
python3 bin/ratd --challenge /path/to/challenge
```

Then in another terminal:

```bash
cd desktop
npm install
npm run tauri dev
```

`ratd` listens on `127.0.0.1:8765` by default. Override the frontend endpoint with:

```bash
VITE_RATD_URL=http://127.0.0.1:8765 npm run tauri dev
```

The solver continues to run through the normal CTF-Rat entrypoints (`rat`, `state`, orchestration, etc.). As STATE v2 events are appended, the desktop timeline updates automatically.

## API

```text
GET /api/health
GET /api/snapshot
GET /api/events?after_seq=<n>&limit=<n>
```

The first implementation is deliberately read-only. Start/stop/intervention controls must later be wired through canonical CTF-Rat execution and verification gates rather than mutating STATE directly.

## Test

```bash
python3 -m unittest tests.test_desktop_api
```

Frontend build check:

```bash
cd desktop
npm install
npm run build
```

## Next milestones

1. PTY terminal stream and local process lifecycle through a bounded session manager.
2. Artifact browser backed by the existing content-addressed store.
3. Function Card / oracle / slice viewers using existing `rat query` envelopes.
4. Solver replay from append-only STATE v2 cursors.
5. User interventions routed through canonical orchestration gates.
