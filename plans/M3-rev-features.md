# M3 — 빈 rev 기능 (싸고 고ROI만)

> **왜**: M1/M2로 배선이 끝난 뒤, 실제로 부족한 rev 기능은 딱 셋 — oracle→symsolve 자동연결,
> difftrace, function-card v2. 진짜 backward *data* slice와 full taint는 비싸고 저ROI라 **descope**
> (레포 doctrine도 "대형 framework로 성급히 교체 금지" 명시). difftrace+compare가 실무에서 대부분 대체한다.

- **브랜치**: `feat/m3-rev-features` (main에서 분기)
- **예상**: 1~2일
- **선행**: M2 완료 (duplicate↓ 증명)

## 현재 상태 (검증된 사실)
- `bin/revq` — success/fail 문자열·xref·interesting은 잡으나 **oracle BB→symsolve 주소 자동연결 없음**(사람 읽는 권고 텍스트뿐, revq:522/553).
- `bin/rat-dyn`(`analysis.py:158-182`) — 단일 시나리오 실행 + 옵션 gdb 레지스터 관찰. **A/B 분기점 로직 없음.**
- `revq --func`(revq:619-630) — callers/calls/strings/blocks는 있으나 **interesting-score·xrefs 미포함**(별 서브커맨드로 분리).

## 설계서 반영 (DESIGN_v2.md — PR6) — 중요한 우선순위 재조정
- **difftrace(옛 M3-2)를 P2로 강등**: 설계서 §16은 differential trace를 **byte-checker/state-machine/VM이 TTF 병목임이 telemetry로 증명될 때만**, 그것도 새 CLI가 아닌 `rat-dyn --compare A B`로 추가한다(P2). Function Card v2의 `compare_sites`(C7) + oracle wiring(C8)이 흔한 checker류에서 difftrace가 주려던 정보 상당부를 먼저 제공하므로, **difftrace는 P2 1순위 후보**로 미루고 M3 후 telemetry에서 byte-wise 병목을 별도 집계한다.
- 따라서 M3의 P1은 **oracle wiring(§14) + Function Card v2(§13) + backward data slice MVP(§15)** 셋으로 고정.
- **모든 출력은 query result envelope(C6)**: `budget_bytes`, item-boundary 절단+`truncated/omitted_count`, 원문은 artifact digest만. status ok|partial|error + error taxonomy.

## 작업 (설계서 §18 PR6 순)

### M3-1 · oracle→symsolve 자동연결 (§14, 가장 쌈, 먼저)
- **변경**: `bin/revq`가 이미 잡은 success/fail 문자열의 xref BB 주소를 뽑아, 복붙 가능한 커맨드를 **문자 그대로 출력**:
  ```
  ORACLE  success@0x1620 (puts "Correct!")  ·  fail@0x1648 (puts "Wrong!")
  SUGGEST symsolve.py <bin> --find 0x1620 --avoid 0x1648 --stdin <n> --printable
  ```
- **주소 규약**: revq 주소 = angr 로드베이스(PIE 0x400000)와 일치(README 명시) → 그대로 투입 가능.
- **§14.1 자동연결 조건**: success/failure 후보가 각각 **단일·명확**하고 xref가 concrete BB로 resolve될 때만 symbolic hint 자동 생성. 후보 다수면 `ambiguous=true`+ranking reasons 반환, **자동 실행 금지**. symbolic candidate는 증거 아님 → 실 바이너리/scenario 실행 concrete verify로만 PASS(local≠remote 유지).
- **파일**: `bin/revq` (interesting/xref 로직 재사용, 새 분석 없음)
- **Acceptance**: rev-checker fixture에서 주소 복붙 없이 symsolve 커맨드 획득. ambiguous fixture에서 자동실행 안 함. `revq selftest` GREEN.

### M3-2 · Function Card v2 (§13, `rat.function-card/v2`)
- **변경**: `revq --func`를 stable JSON 하나로 확장. 설계서 스키마 준수 — `facts`(deterministic only)/`heuristics`(score+reasons+detector version)/`unresolved`(indirect/truncated 숨김 금지)/`next` 분리.
- **facts**: `callers`, `callees`, `strings`, `input_apis`, `compare_sites:[{address,api,length}]`, `oracle_candidates:[{kind:success|failure,xref,string}]`.
- **원칙**: 서브커맨드 3개(`--func`/`--interesting`/`--xrefs`)를 합쳐 호출 1회. LLM prose 금지. revmap/decomp digest를 provenance로 연결.
- **파일**: `bin/revq`
- **Acceptance**: `revq --func`가 <1.5K토큰 stable JSON(facts/heuristics/unresolved 분리), compare/oracle candidate detector false-positive fixture 통과, selftest GREEN.

### M3-3 · Bounded backward data slice MVP (§15, `--mode data`)
- **변경**: `rat query slice --mode data --backward <addr> --source stdin --depth 2`. within-func def/use·register·stack-local·direct-call summary. interproc depth≤2. heap/global alias·indirect full resolution = NO(unresolved 보고). full-program taint = REJECT.
- **결과 계약**: 미해결 alias/indirect 있으면 `claim: dependency-candidate`(proof 아님), `unresolved_aliases/unresolved_indirect_calls` 명시.
- **파일**: `bin/ratlib/analysis.py`(slice data mode), 기존 call-path 모드는 유지.
- **Acceptance**: known def-use fixture 통과, alias-unresolved fixture에서 proof 승격 안 함, depth budget 강제. `tests/test_p2_analysis.py` 확장.

### M3-4 · 통합 검증 (측정)
- **작업**: M3 반영 후 동일 fixture로 telemetry 기록, `tests/telemetry/ab_M3.jsonl`.
- **Acceptance**: REV time-to-first-valid-candidate 감소(oracle wiring), functions_decompiled/raw_output 감소(Function Card v2). release gate 추적.

## Descope → P2 (설계서 §16, telemetry 병목 증명 후에만)
- **Differential trace = P2 1순위**: `rat-dyn --compare A B`. byte-checker/state-machine/VM이 TTF 병목임이 telemetry로 증명될 때만. (Function Card compare_sites + oracle wiring이 먼저 상당부 대체)
- Constraint extractor(Function Card compare facts 확장부터), syscall/seccomp observer, allocator event collector, coverage fuzz adapter, rr/replay
- semantic(L2) cache = **REJECT v2.0** (deterministic fact 아님, auto-inject 금지)

## 완료 게이트
- [ ] M3-1 oracle→symsolve 자동연결 (§14.1 조건: 단일·명확 후보만 자동, 다수면 ambiguous)
- [ ] M3-2 function-card v2 (facts/heuristics/unresolved 분리, 스키마 준수)
- [ ] M3-3 backward data slice MVP (dependency-candidate claim, unresolved 표기)
- [ ] M3-4 telemetry에서 REV TTF/decompile 호출 감소 증명
- [ ] 회귀: `revq selftest`, `symsolve selftest`, `test_p2_analysis` 전부 GREEN

## 롤백
- 전부 기존 도구에 서브모드/필드 추가 → 플래그 없이 호출 시 기존 동작 유지. 브랜치 원복으로 제거.
