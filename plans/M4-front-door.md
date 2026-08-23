# M4 — Single Front Door `rat` + Operator Skills + Query Envelope

> 설계서 §11/§12/§17(PR5)에서 신규 도출. `rat`는 새 분석 엔진이 아니라 **thin dispatcher**로,
> 기존 binary를 compatibility adapter로 감싸 하나의 canonical UX를 만든다. ADR-007.
> 원안(M1)에서 `rat-route`를 독립 CLI로 두려던 걸 여기로 흡수한다(한 PR=한 가설).

- **브랜치**: `feat/m4-front-door` (main에서 분기)
- **예상**: 1일
- **선행**: M1(route 판정 로직 ratlib), M2(canonical cache), M3(query 대상들)
- **참조**: DESIGN_v2.md C6/C8, 설계서 §11·§12·§17

## 작업

### M4-1 · `bin/rat` thin dispatcher
- **신규**: `bin/rat` — 서브커맨드 `route | query func | query oracle | query slice | dyn | verify | state compact | cache stats`.
- **원칙**: 각 서브커맨드는 기존 구현(revq/analysis/state/rat-verify)을 호출하는 얇은 어댑터. 새 엔진 금지.
- **파일**: `bin/rat`
- **Acceptance**: 각 서브커맨드가 기존 CLI와 결과 의미 호환(golden/e2e). legacy 명령 제거 안 함.

### M4-2 · `rat route` (§11.1 route-result/v1)
- **변경**: M1에서 만든 route 판정 로직(ratlib)을 `rat route`로 노출. 출력 `rat.route-result/v1`:
  `{track, subroute, confidence, signals:[{kind,value,quality}], capabilities:{native,angr,ghidra}, skill, next:[{query,target}]}`.
- **invariants(§11.2)**: confidence는 heuristic(fact와 분리). 기본 skill 1개만, 복수는 `alternatives`로 명시하되 자동 동시 로드 금지. capability missing은 route 실패가 아니라 degradation reason. route result는 artifact digest+source signal로 재현 가능.
- **Acceptance**: 동일 profile/signals→동일 subroute/skill. `tests/test_route.py`.

### M4-3 · Operator Skill Layer (§12)
- **신규**: `skills/{rev-checker,rev-vm,rev-packed,rev-symbolic,pwn-stack,pwn-format,pwn-heap,pwn-rop,pwn-kernel}/SKILL.md`.
- **포맷**: **SIGNALS · FIRST ACTION · PIVOT · ESCALATE · VERIFY** 섹션만. knowledge/는 reference로 유지, 복제 금지. 파일이 커지면 route 분류 오류.
- **Acceptance**: route가 반환한 skill 1개만 hot-path 로드. 각 skill이 signal→action→verify로 연결.

### M4-4 · Query result envelope + budget + error taxonomy (§17)
- **변경**: query 계열 출력을 `rat.query-result/v1`로 통일 — `{query, status(ok|partial|error), facts, heuristics, artifacts, coverage{complete,scope,omitted}, diagnostics, provenance{...,cache}}`.
- **budget(§17.2)**: 모든 query에 `budget_bytes`. 초과 시 item boundary 절단+`truncated/omitted_count`. 원문은 artifact digest만.
- **error taxonomy(§17.3)**: `input_invalid/dependency_missing/timeout/partial/stale_cache/ambiguous/verification_fail` + 재시도 정책.
- **Acceptance**: query 출력 스키마 validation, budget 초과 시 item-boundary 절단 테스트, 각 error code 재현 fixture.

### M4-5 · Progress Novelty Governor 구현 (§8.3, C10)
- **변경**: M1에서 명문화한 governor를 `rat` 루프 훅으로 구현 — 최근 5회 query에서 novelty(새 artifact digest/finding revision/ruled-out route/primitive change) 0이면 re-route 또는 DEEP escalation reason 기록.
- **Acceptance**: novelty-0 시퀀스 fixture에서 escalation reason 기록.

## 완료 게이트
- [ ] `bin/rat` dispatcher + 서브커맨드 golden/e2e 호환
- [ ] `rat route` route-result/v1 + invariants + test_route
- [ ] operator skill 9종 (SIGNALS/FIRST ACTION/PIVOT/ESCALATE/VERIFY)
- [ ] query-result/v1 envelope + budget + error taxonomy 테스트
- [ ] Progress Novelty Governor 훅
- [ ] release gate: duplicate path·route latency 감소 (V2-A4 ablation)

## Migration/Rollback (§22)
- legacy revq/decomp/state/rat-* CLI 유지(dual path 제거 안 함). `rat`은 canonical, 나머지는 adapter.
- feature flag로 `rat` 경로 독립 rollback.

## 롤백
- `bin/rat`·`skills/`는 신규라 제거로 원복. 기존 CLI 무변경.
