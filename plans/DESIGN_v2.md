# CTF-Rat v2 — Query-First Solver Runtime (canonical 설계 spec)

> 출처: `CTF-Rat_v2_Architecture_Design_KO.pdf` (2026-08-23, snapshot main 01a1a9a / dev a6e6720).
> 이 문서는 그 설계서를 레포의 **binding spec**으로 요약·정착시키고, M0~M3 실행계획이 매핑되는 계약을 고정한다.
> 검토자 주석은 `> 검토:` 로 표기.

## 최상위 불변식 (설계서 §1.1)
1. **Correctness first** — FAST는 검증 생략 모드가 아니다. SOLVED/PASS/VERIFIED/FIXED엔 executable oracle·test·schema·benchmark 실제 증거 필요.
2. **One concept → one canonical implementation** — revq/decomp/ratlib가 같은 정보를 별도 캐시·스키마로 장기 유지하지 않음.
3. **Repository/artifact = long-term truth**, model context = 현재 working set만.
4. **Measurement before architecture claims** — 동일 corpus·환경·timeout 전후 수치로 증명.
5. **Deterministic fact ≠ interpretation** — LLM semantic summary는 자동 캐시 주입 금지.

핵심 순서(변경 불가): `measure → slim → unify cache → compact context → query front door → oracle wiring → bounded data slice`

## 아키텍처 원칙 (§5, 요약)
A1 Query First · A2 FAST Default · A3 DEEP Conditional · A4 Verification Invariant · A5 Canonical Path ·
A6 Artifact Truth · A7 Cache Deterministic Facts · A8 Measurement/Ablation · A9 Budget Every Output · A10 No Feature Inflation.

---

## Binding 계약 (구현이 반드시 따를 스키마/정의)

### C1. duplicate_tool_calls = operation_fingerprint 중복 (§7.2)
command 문자열 중복이 아니라 canonical operation fingerprint 중복으로 집계. **cache hit은 중복 "실행"으로 세지 않되 `cache_requests`에는 포함.**
```
operation_fingerprint = sha256({
  tool:{name, build_digest}, inputs:sorted(input_digests),
  parameters:normalized, dependencies:versions, policy_digest, output_schema })
```

### C2. Benchmark result v2 필수 필드 그룹 (§7.1)
- correctness: `verified_solve, false_solved, oracle_pass`
- latency: `time_to_first_query, time_to_first_hypothesis, time_to_first_valid_primitive, time_to_verified_solve`
- context: `input_tokens, output_tokens, peak_context_tokens, tool_output_bytes`
- tools: `tool_calls, duplicate_tool_calls, ghidra_runs, cfgfast_runs, symbolic_runs, subagent_count`
- cache: `cache_requests, cache_hits, cache_hit_ratio, bytes_reused, cold_warm`
- reasoning: `hypotheses_created, hypotheses_refuted, pivot_count, deep_escalations`
- artifacts: `functions_decompiled, raw_output_size, compressed_output_size, artifact_count`
- 단위(ms/bytes/tokens/count)를 schema에 고정.

### C3. Canonical cache key v2 (§9.1) + hit envelope fix (§9.3)
```
rat.cache-key/v2 = sha256(canonical_json({
  artifact_inputs:[{role,digest,size}], tool:{name,version,build_digest},
  parameters:normalized, dependencies:exact_versions_or_digests,
  policy_digest, output_schema, analysis_schema_version }))
```
**hit envelope fix**: cache hit 시 artifact는 재사용하되 **invocation envelope는 새로 생성**한다 —
`{invocation_id: new, status: ok, artifacts:[reused refs], provenance.cache:{key, hit:true, source_invocation: old}}`.
(현재 `contracts.py`는 저장된 옛 envelope를 그대로 반환해 `hit=false`가 남음 — 이걸 고침.)

### C4. 자동 재사용 허용/금지 (§9.4)
- YES(자동): ELF/file profile, symbols/imports, strings/xrefs, CFG, function boundary, Ghidra decompile, ROP gadgets, deterministic Function Card facts (partial/truncated/stale 제외)
- 조건부: dynamic trace (scenario/environment digest가 key에 포함될 때만)
- **NO(v2.0)**: LLM semantic summary/hypothesis/prose

### C5. state compact = bounded projection (§10) — 우선순위
1 invalidating alerts(절대유지) · 2 confirmed facts(절대유지) · 3 PASS primitives+env digest(절대유지) ·
4 active hypotheses(낮은 우선순위부터 drop) · 5 next probes(상위 N) · 6 recent ruled-out(최근/관련만) · 7 notes/old(기본 drop).
출력에 `truncated/omitted_counts/cursor` 명시. 동일 cursor+policy+max-bytes → deterministic.

### C6. Query result envelope + Output budget + Error taxonomy (§17)
- `rat.query-result/v1`: `{query, status(ok|partial|error), facts, heuristics, artifacts, coverage{complete,scope,omitted}, diagnostics, provenance{...,cache}}`
- 모든 query에 `budget_bytes`. 초과 시 **item boundary**에서 절단 + `truncated/omitted_count`. 원문 필요하면 artifact digest만 반환.
- error codes: `input_invalid, dependency_missing, timeout, partial, stale_cache, ambiguous, verification_fail` (각 재시도 정책 §17.3).

### C7. Function Card v2 (§13) — `rat.function-card/v2`
`facts`(deterministic only: callers/callees/strings/input_apis/compare_sites/oracle_candidates) · `heuristics`(score/reasons+detector version) · `unresolved`(indirect/truncated 숨김 금지) · `next`. LLM prose 금지. revmap/decomp digest를 provenance로 연결.

### C8. Oracle wiring 자동연결 조건 (§14.1)
success/fail 후보가 각각 단일·명확 + xref가 concrete BB로 resolve될 때만 symbolic hint 자동생성. 다수면 `ambiguous=true`+ranking, 자동실행 금지. symbolic candidate는 증거 아님 → 실 바이너리 실행 concrete verify로만 PASS.

### C9. Bounded backward data slice MVP (§15)
`rat query slice --mode data --backward <addr> --source stdin --depth 2`. within-func def/use·register·stack-local·direct-call summary YES, interproc depth≤2, heap/global alias·indirect full resolution NO(unresolved 보고), full-program taint REJECT v2.0. 미해결 alias/indirect 있으면 결과를 "proof"로 승격 금지 — `claim: dependency-candidate`.

### C10. Progress Novelty Governor (§8.3)
시간 기반 stuck 판정 대신 최근 5회 tool/query에서 새 artifact digest·finding revision·ruled-out route·primitive status change가 하나도 없으면 강제 re-route 또는 DEEP escalation reason 기록.

---

## Operator Skill 포맷 (§12) — hot-path 전용, doctrine 복제 아님
`skills/{rev-checker,rev-vm,rev-packed,rev-symbolic,pwn-stack,pwn-format,pwn-heap,pwn-rop,pwn-kernel}/SKILL.md`
허용 섹션: **SIGNALS · FIRST ACTION · PIVOT · ESCALATE · VERIFY** 만. 파일이 커지면 route 분류가 잘못된 것.

## 단일 Front Door `rat` (§11) — thin dispatcher
`rat route|query func|query oracle|query slice|dyn|verify|state compact|cache stats`. 새 엔진 아님, 기존 binary는 compatibility adapter. `rat.route-result/v1`에 track/subroute/confidence/signals/capabilities/skill/next.

---

## Release Gate (§21) — v2 채택 판정 (초기 target, PR1 후 corpus로 조정)
| 지표 | target | 판정 |
|---|---|---|
| false SOLVED | 0 | **하드 게이트** |
| verified solve rate | ≥ v1 | **하드 게이트** |
| median time-to-verified-solve | ≤ 70% of v1 | 성능 |
| median peak context | ≤ 55% of v1 | 효율 |
| tokens / verified solve | ≤ 65% of v1 | 효율 |
| duplicate tool executions | ≤ 25% of v1 | orchestration |
| warm deterministic cache hit ratio | ≥ 70% | cache |
| easy REV unnecessary DEEP rate | ≤ 10% | routing |

## ADR (부록 B) — 확정 결정
001 FAST default/DEEP conditional · 002 ratlib cache canonical(새 cache 금지) · 003 state compact 강화(새 state DB 금지) ·
004 revq Function Card v2(새 CLI 금지) · 005 semantic cache auto-inject **Rejected v2.0** · 006 full taint first **Rejected** ·
007 single front door `rat` · 008 verification hard invariant.

## Migration/Rollback (§22) — 파괴 금지
계측 → canonical 결정 → thin adapters → **dual-read/single-write**(legacy read 허용, write는 canonical) → compat test → deprecation telemetry. 각 PR은 feature flag로 독립 rollback. immutable artifact 삭제 금지. STATE 파괴적 migration 금지(compact는 view-only). legacy CLI 제거 안 함.

---

## PR(설계서 §18) ↔ 본 레포 마일스톤 매핑
| 설계서 PR | 본 계획 | 비고 |
|---|---|---|
| PR1 Measurement First | **M0** | C1·C2 채택해 강화 |
| PR2 Slim Runtime | **M1** (§8) | + Progress Novelty Governor(C10), operator skill 포맷 |
| PR3 Canonical Cache | **M2** (§9) | + hit envelope fix(C3), dual-read/single-write |
| PR4 Context Projection | **M1-4 → 확장** | state compact 우선순위(C5) — M1에 포함하되 Function Card v2와 함께 |
| PR5 Query Front Door | **신규 M4** | `rat` dispatcher + query envelope(C6) + operator skills |
| PR6 REV Acceleration | **M3** (§13,14,15) | Function Card v2(C7)·oracle wiring(C8)·slice MVP(C9) |
| PR7 Conditional | **M5(조건부)** | difftrace/constraint/pwn observers — telemetry 병목 증명 후 |

> 검토: 내 원안은 PR4(context projection)를 M1에 얹고 front door를 M1에 섞었으나, 설계서대로 **front door를 독립 M4로 분리**하는 게 맞다(한 PR=한 가설, attribution 가능).

## 주요 검토 결론 (설계서 vs 내 원안)
- **일치**: 순서, 캐시 통합, slim entrypoint, state compact 강화(새 subsystem 금지), Function Card v2, oracle wiring, semantic cache 거부. cache.hit 버그도 양측 독립 발견 → 교차검증됨.
- **보강 채택**: operation_fingerprint(C1), benchmark v2 필드(C2), hit envelope fix 방식(C3), query envelope/error taxonomy(C6), Progress Novelty Governor(C10), operator skill 포맷, release gate, ADR, dual-read/single-write migration.
- **재조정 1건 — difftrace 강등**: 내 M3는 difftrace를 P0급 "ROI 최상"으로 뒀으나, 설계서는 **P2**(byte-checker/state-machine/VM이 TTF 병목임이 telemetry로 증명될 때만, 그것도 새 CLI 아닌 `rat-dyn --compare A B`)로 둔다.
  > 검토 판단: **설계서를 채택**한다. 이유 — Function Card v2의 compare_sites(C7) + oracle wiring(C8)이 흔한 checker류에서 difftrace가 주려던 정보의 상당부를 먼저 제공하므로, difftrace는 그 뒤 실측 병목이 남을 때 붙이는 게 규율에 맞다. 단 **difftrace는 P2 1순위 후보**로 명시하고 M3 후 telemetry에서 byte-wise 병목을 별도 집계한다.
- **환경 보강(설계서 미기재)**: 설계서 §20이 요구하는 "고정된 model/env/timeout/tool-versions"의 구체 구현이 `docker/dev`(chore/dev-env, Linux x86_64 + angr/pwntools/gdb)다. benchmark attribution의 전제 환경으로 이걸 사용한다.
