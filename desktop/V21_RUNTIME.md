# Desktop ↔ CTF-Rat v2.1 runtime contract

The Desktop workbench is synchronized with the `dev` v2.1 runtime as of the merge of `f86ce721b406a07b20bb93d35552008b9d9cbf2e`.

This synchronization does **not** make Desktop a solver implementation. `rat`, STATE v2, the content-addressed artifact/cache infrastructure, orchestration, verification, completion, and session metrics remain canonical runtime components. Desktop only exposes bounded read projections plus the existing preconfigured local PTY control surface.

## New v2.1 projections

### Verified completion

`GET /api/completion` wraps `ratlib.completion.completion_gate()` directly.

The UI may display `VERIFIED` only when that canonical gate returns `verified: true`. A primitive `PASS` by itself is deliberately not displayed as a solved challenge. The gate re-authenticates the active `rat-verify` report and its primitive/exploit-task lineage.

Desktop does not maintain a parallel solved flag.

### Session metrics

`GET /api/telemetry` keeps the existing STATE event/group counters and now includes the canonical `rat.session-metrics/v1` projection from `ratlib.metrics`.

The current UI surfaces a bounded operational subset:

- process/tool-result tool calls
- duplicate tool calls
- cache hit ratio
- functions decompiled

The underlying metrics document also retains primitive/verified-solve latency and backend index counts. Unknown or unobserved values remain unknown/null; the UI must not fabricate zero for canonical measurements that are unavailable.

Telemetry is not polled on the 500 ms idle hot path. The UI refreshes it when the artifact inventory changes, which is a practical hint that tool output may have changed. This preserves the low-cost generation-token STATE polling path.

### STATE v2.1 additions

The materialized STATE view now includes the runtime's canonical `alerts`, `failures`, and `notes` projections in addition to observations/findings/primitives/hypotheses/unknowns/next probes.

Desktop currently displays:

- failure and alert counts in the STATE sidebar
- the latest classified failure in the focus strip
- `FAIL`, `ALERT`, `EVID`, and `VERIFY` event groups in the Activity Timeline

These values are projections of STATE events; Desktop does not classify failures itself.

## Compatibility rules

1. Desktop adapters must follow current STATE validation rules rather than weakening them for old fixtures.
2. Migration fixtures must satisfy the v2.1 migration provenance contract.
3. `desktop-workbench` CI is triggered by changes to Desktop's canonical runtime dependencies (`artifact`, `cache`, `completion`, `metrics`, `orchestration`, and `state_v2`).
4. `/api/live` remains the STATE hot path and still reuses canonical `Stream.view()` semantics.
5. `/api/completion` is read-only. Solver control remains limited to the single daemon-configured argv plus bounded PTY input.
6. No free-form HTTP command execution, second state database, second cache, or Desktop-specific verification state is introduced.

## UI truth rules

- `VERIFIED` means canonical `completion_gate == true` only.
- primitive/finding/failure labels are rendered from canonical STATE projections.
- cache/tool metrics are descriptive telemetry, not evidence of solve correctness.
- historical replay remains a STATE projection and must not rewrite live completion truth.
- colors are supplemental; textual status remains present per `DESIGN.md`.

## Validation

For this synchronization, the required gates are:

- Desktop backend/API/session/HTTP/E2E tests
- STATE polling and artifact discovery measurement harnesses
- TypeScript/Vite production build
- `cargo check --locked`
- Linux `.deb` and AppImage build/validation
- repository operational regression inherited from the current `dev` runtime

The Desktop pull request stays draft while these gates or concurrent real-session telemetry work are unresolved.
