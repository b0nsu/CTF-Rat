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

## 완료 게이트
- [ ] CLAUDE.md ≤1.5K토큰, 7줄 hot-path
- [ ] doctrine lazy, FAST 경로 doctrine 0로드
- [ ] `rat-route` fixture 정확 + `tests/test_route.py`
- [ ] `state compact --budget-tokens` 동작
- [ ] M1-5 A/B에서 context↓ 증명

## 롤백
- CLAUDE.md는 git 원복. `rat-route`는 신규 파일(제거로 원복). state 플래그는 기존 동작 미변경(추가만).

## 다음
context_peak 감소 증명 후 M2.
