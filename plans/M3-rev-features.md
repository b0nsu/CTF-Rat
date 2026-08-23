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

## 작업 (ROI 순)

### M3-1 · oracle→symsolve 자동연결 (가장 쌈, 먼저)
- **변경**: `bin/revq`가 이미 잡은 success/fail 문자열의 xref BB 주소를 뽑아, 복붙 가능한 커맨드를 **문자 그대로 출력**:
  ```
  ORACLE  success@0x1620 (puts "Correct!")  ·  fail@0x1648 (puts "Wrong!")
  SUGGEST symsolve.py <bin> --find 0x1620 --avoid 0x1648 --stdin <n> --printable
  ```
- **주소 규약**: revq 주소 = angr 로드베이스(PIE 0x400000)와 일치(README 명시) → 그대로 투입 가능.
- **파일**: `bin/revq` (interesting/xref 로직 재사용, 새 분석 없음)
- **Acceptance**: rev-checker fixture에서 사람이 주소 복붙 없이 symsolve 커맨드 획득. `revq selftest` GREEN.

### M3-2 · difftrace (A/B 첫 분기점) — ROI 최상위
- **변경**: `bin/rat-dyn`에 `difftrace` 서브모드 추가. 입력 A/B를 각각 실행(기존 단일 실행 경로 2회)해
  **첫 갈라지는 basic block + 그 지점 레지스터/입력바이트 diff**만 출력:
  ```
  FIRST DIVERGENCE  block 0x158a  (cmp eax, 0x31)
  A: eax=0x30  jne taken      B: eax=0x31  jne not-taken
  LIKELY INPUT DEP  stdin[4]
  ```
- **엔진**: 기존 gdb 배치 훅(`analysis.py:167-175`) 재사용 — BB 단위 트레이스(`gdb -batch` stepi/hbreak) 또는 가용 시 경량 트레이서. gdb 없으면 `status:partial`.
- **한계 명시**: `P2_LIMITATIONS["rat-dyn-difftrace"]=["single-run traces compared; not symbolic; remote equivalence unproven"]` (기존 패턴 준수, 비프로모션).
- **파일**: `bin/rat-dyn`, `bin/ratlib/analysis.py`
- **Acceptance**: serial/byte-checker fixture에서 분기 유발 입력 바이트 특정. `tests/test_p2_analysis.py`에 케이스 추가.
- **대상 클래스**: serial checker, byte-by-byte, VM, CRC/checksum, state machine, maze, anti-analysis.

### M3-3 · Function Card v2 (합치기)
- **변경**: `revq --func`를 stable JSON 하나로 확장 — 기존 callers/calls/strings/blocks + **interesting-score**(기존 `--interesting`)·**xrefs**(기존 `--xrefs`)·**compare 대상**(memcmp/strcmp 인자+길이)·**oracle distance**(success/fail BB까지 블록 수)를 한 카드에 병합.
- **원칙**: 서브커맨드 3개(`--func`/`--interesting`/`--xrefs`)를 **합쳐서 호출 1회**로. 새 분석 최소, 기존 결과 조립.
- **출력 예**:
  ```json
  {"func":"check_flag","addr":"0x1450","role":"checker",
   "callers":["main"],"calls":["transform","memcmp"],
   "compare":[{"fn":"memcmp","target":"0x404080","len":32}],
   "oracle":{"success":"0x1620","fail":"0x1648"},
   "interesting":0.94,"xrefs":[...], "next":"rat-dyn difftrace ..."}
  ```
- **파일**: `bin/revq`
- **Acceptance**: `revq --func`가 <1.5K토큰 stable JSON, 3개 서브커맨드 정보 통합. selftest GREEN.

### M3-4 · Sol 승격 실험
- **작업**: M3 반영 후 동일 fixture로 Terra medium vs Sol medium A/B, `tests/telemetry/ab_M3_model.jsonl` 기록.
- **Acceptance**: `verified_solve`·`time_to_flag` 비교표. 결론에 따라 기본 solver 모델 권고 확정(아키텍처 정리 후 hard는 Sol 기본).

## Descope (P2 — fixture가 병목 2회 입증할 때만)
- 진짜 backward data-slice(def-use/taint), full program taint
- compare/constraint extractor(자동 역연산 힌트), syscall/seccomp observer
- allocator event collector, semantic(L2) cache(반드시 `unverified` 태그)

## 완료 게이트
- [ ] M3-1 oracle→symsolve 커맨드 자동생성
- [ ] M3-2 difftrace fixture 분기 특정 + 비프로모션 한계 명시
- [ ] M3-3 function-card v2 통합 JSON
- [ ] M3-4 Terra vs Sol A/B 표
- [ ] 회귀: `revq selftest`, `symsolve selftest`, `test_p2_analysis` 전부 GREEN

## 롤백
- 전부 기존 도구에 서브모드/필드 추가 → 플래그 없이 호출 시 기존 동작 유지. 브랜치 원복으로 제거.
