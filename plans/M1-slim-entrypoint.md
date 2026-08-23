# M1 — 슬림 진입점 + FAST/DEEP + rat route

> **왜 최대 ROI인가**: "컨텍스트가 빨리 찬다"의 직접 원인. 시작마다 CLAUDE.md(113줄)+doctrine 4종
> (~280줄, 3~5K토큰)이 강제 로드되고, STATE 원본이 컨텍스트에 상주한다. 코드 변경 최소, 문서·규칙 위주.

- **브랜치**: `feat/m1-slim-entrypoint` (main에서 분기)
- **예상**: 반나절
- **새 분석 능력**: `rat route`는 기존 profile/revq 신호 재사용 — 새 분석 로직 없음
- **선행**: M0 완료 (baseline 확보)

## 현재 상태 (검증된 사실)
- `CLAUDE.md:10-13` 읽는 순서 강제: SOLVING(60)→SOLVABILITY(57)→PRIMITIVE_GATE(78)→GROUNDING_INDEX(85).
- router-first 진입점 없음. GROUNDING_INDEX가 라우터 역할이나 doctrine 3종 뒤 4번째.
- `state compact`/`state delta --max-bytes`는 존재하나 **token 예산** 컷은 없음(byte 근사만).

## 작업

### M1-1 · CLAUDE.md 7줄 hot-path로 축소
- **남길 것 (FAST hot-path)**:
  1. 단일 명시 대상 ROE (로컬 우선 + 사용자 지정 단일 remote만)
  2. 목표 = 실제 verifier/flag까지, honest-mode
  3. 시작 = `rat route <bin>`
  4. route 결과에 맞는 skill/knowledge **1개만** 로드
  5. raw dump 금지 — bounded query(`revq --func`, `state compact`) 사용
  6. 실패/모호/remote-sensitive pwn → **DEEP 승격**
  7. 성공 주장 = 결정론적 verify(`rat-verify`) 필요
- **DEEP 블록**: doctrine 4종·PRIMITIVE_GATE·SOLVABILITY 링크를 "DEEP에서만 로드" 섹션으로 이동.
- **파일**: `CLAUDE.md` (AGENTS.md는 심볼릭이라 자동 반영)
- **Acceptance**: CLAUDE.md 자동로드 분량 ≤ 1.5K토큰. FAST 예제 세션에서 doctrine 미참조.
- **주의(prompt cache)**: hot-path를 stable prefix로. challenge/state/tool-result는 append-only 뒤쪽에.

### M1-2 · doctrine lazy-load 재배선
- **변경**: `doctrine/SOLVING.md` 등의 "읽는 순서" 강제 문구를 "DEEP 진입 또는 명시 요청 시 로드"로 완화.
- **파일**: `CLAUDE.md`, `doctrine/SOLVING.md` 상단, `README.md`(진입점 설명)
- **Acceptance**: FAST 경로에서 doctrine 0회 로드로 rev checker fixture 진행 가능.

### M1-3 · `bin/rat-route` 결정론적 라우터
- **신규 파일**: `bin/rat-route <bin> [--format text|json]`
- **동작**: 기존 `rat-profile`(checksec/imports/format) + `revq`(interesting/evasion) 신호만 조합해
  route + confidence 출력. **새 분석 없음, 기존 아티팩트/캐시 재사용.**
- **route 라벨(초기)**: `rev-checker`, `rev-vm`, `rev-packed`, `pwn-stack`, `pwn-fmt`, `pwn-heap`, `pwn-kernel`, `unknown`
- **판정 근거 예**: UPX/high-entropy → rev-packed; VM 디스패치 패턴 → rev-vm; memcmp/strcmp+success str → rev-checker; gets/format import → pwn-*; `__libc_csu`+heap sym → pwn-heap.
- **출력(text)**:
  ```
  ROUTE  rev-checker
  CONF   0.91
  CACHE  profile HIT · revmap HIT
  NEXT   rat func <interesting>
  ```
- **파일**: `bin/rat-route`
- **Acceptance**: fixture별 route가 기대와 일치(테스트), 출력 <2K토큰, confidence 포함.

### M1-4 · `state compact --budget-tokens`
- **변경**: 기존 `state compact` projection에 token 예산 플래그 추가(초과 시 오래된 hypotheses/ruled_out부터 절삭, facts·next는 보존 우선).
- **파일**: `bin/state`
- **Acceptance**: `state compact --budget-tokens 1200` 이 예산 내 facts/hyp/dead/next만 출력. 원본 STATE.jsonl 불변.
- **규칙화**: CLAUDE.md에 "컨텍스트엔 `state compact`만, STATE 원본 금지" 명문화.

### M1-5 · A/B 측정
- **작업**: slim+Terra vs 기존+Terra 를 동일 fixture 3개로 실행, `rat-metrics`로 비교, `tests/telemetry/ab_M1.jsonl` 기록.
- **Acceptance**: `context_peak`(또는 tokens/solve) 유의미 감소 증거. 감소 없으면 M2 착수 보류 후 원인 분석.

## 설계서 반영 (DESIGN_v2.md — PR2/PR4)
- **7개 규칙 확정(§8.1)**: root contract는 ①CTF/local ROE+금지 ②목표=verifier/flag+증거 ③첫 동작 `rat route` ④선택된 operator skill 1개만 ⑤raw dump보다 bounded query ⑥불확실/env민감/repeated failure/evidence conflict면 DEEP ⑦SOLVED/PASS는 deterministic verify 없이는 금지.
- **FAST 기본 비활성 표(§8.2)**: full doctrine preload/full STATE/raw Ghidra/fan-out/skeptic/full CFG·symbolic/scout subagent = 전부 OFF. 각 DEEP 조건 명시.
- **C10 Progress Novelty Governor 추가**: 시간 기반 stuck 대신 최근 5회 tool/query에서 새 artifact digest·finding revision·ruled-out route·primitive status change가 없으면 강제 re-route 또는 DEEP escalation reason 기록. → `bin/rat`(M4) 또는 governor 헬퍼에 구현, M1에선 규칙 명문화 + hook 지점 확보.
- **operator skill 포맷(§12)**: `skills/<route>/SKILL.md`는 **SIGNALS·FIRST ACTION·PIVOT·ESCALATE·VERIFY** 섹션만. knowledge/는 reference로 유지, 복제 금지.
- **C5 state compact 우선순위(§10.1)**: `--budget-tokens`는 우선순위(invalidating>confirmed>PASS primitive>active hyp>next>recent ruled-out>notes)로 절삭하고 `truncated/omitted_counts/cursor` 출력. 동일 cursor+policy+budget → deterministic.
- **재조정**: 독립 `bin/rat-route`를 만들지 않고 **M4의 `rat route` 서브커맨드로 흡수**(§11, ADR-007 single front door). M1에선 route 판정 로직만 라이브러리(`ratlib`)로 구현하고 CLI 노출은 M4에서.

## 완료 게이트
- [ ] CLAUDE.md ≤1.5K토큰, 7줄 hot-path(§8.1) + FAST 비활성 표
- [ ] doctrine lazy, FAST 경로 doctrine 0로드
- [ ] route 판정 로직(ratlib) + `tests/test_route.py` (동일 profile/signals→동일 subroute, missing capability degradation)
- [ ] `state compact --budget-tokens` 우선순위 projection + deterministic 테스트
- [ ] operator skill 9종 스캐폴드(SIGNALS/FIRST ACTION/PIVOT/ESCALATE/VERIFY)
- [ ] Progress Novelty Governor 규칙 명문화 + hook 지점
- [ ] M1-5 A/B에서 context↓ 증명 (release gate: peak context ≤55%, easy-REV unnecessary-DEEP ≤10% 추적 시작)

## 롤백
- CLAUDE.md는 git 원복. `rat-route`는 신규 파일(제거로 원복). state 플래그는 기존 동작 미변경(추가만).

## 다음
context_peak 감소 증명 후 M2.
