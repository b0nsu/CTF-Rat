# PR 리뷰 반영 결합 및 머지 결과 (2026-10-17~18)

기준: `origin/dev` (`b73348d`). 별도 작업 트리
`/home/ctfrat/바탕화면/CTF-Rat-pr-integration`에
**#109 → #115 → #108 → #111 → #97 → #113 → #114** 순서로 각 PR의
base 대비 변경을 적용했다. 작업 시작 시 일곱 PR은 모두 OPEN이었고 HEAD는
각각 `4832274`, `370f66d`, `35d504a`, `e82ba59`, `95d9975`,
`6e91c9f`, `038c39c`였다. 결합 트리를 검증한 뒤 리뷰 수정 사항을 원래
PR 브랜치에 반영하고, 일곱 PR을 아래 순서로 `dev`에 squash 머지했다.

| PR | `dev` 머지 커밋 |
| --- | --- |
| #109 | `8a09fb9` |
| #115 | `ee1573d` |
| #108 | `91e3b82` |
| #111 | `e887525` |
| #97 | `6f69cae` |
| #113 | `08c94a3` |
| #114 | `1df29bb` |

최종 `dev`의 코드 트리는 검증된 결합 트리와 같다. 통합 PR #116은
순차 머지 방식을 선택한 뒤 닫았고, 무관한 #110과 #13은 변경하지 않았다.

## 리뷰 반영

- **#109:** challenge-local 형식 및 symlink 거부 변경을 결합했다. `REAL`은
  형식 일치이며 flag 정답 검증을 뜻하지 않는다.
- **#115:** `cmd_eval`의 사전 검사는 첫 셸 command word만 파싱한다.
  `/bin/sh -c`에서 실행되는 중첩 명령 치환, 인용된 실행 파일, 없는 실행
  파일을 회귀 테스트로 확인했다.
- **#108:** `newchal`은 `rat route --format json`의 `analysis_failed`를
  검사한다. 종료 코드 0이어도 분석이 실패했다면 `ROUTE UNKNOWN`을
  `state.md`와 화면에 남긴다. 일반적인 `provisional`은 성공 경로로 둔다.
  PE에서 `--fast`를 강제하지 않는 회귀도 통과했다.
- **#111:** heap 읽기 timeout을 timeout으로 전달하는 변경과 모의 heap
  layout 테스트를 결합했다.
- **#97:** PWN 카드 뒤 `route`의 `next`가 stack 후보에 `pwncrash`,
  format/heap 후보에 선택된 caller의 `decomp`를 제시한다. caller 정보가
  없으면 교체할 placeholder가 표시된다. 경쟁 lead에서는 `decision=null`
  이며, 카드 결과로 primitive PASS나 refutation을 만들지 않는다. 단일
  stack 후보의 `route → query pwn → route` 통합 테스트와 competing lead,
  concrete caller 테스트가 통과했다.
- **#113:** image-base 주소 변환, cache seal, 자식 종료 코드 보존 변경을
  #114보다 먼저 결합했다.
- **#114:** #97과 합친 Router v2에서 Wasm route·brief·probe ID·feedback을
  검증했다. Wasm에는 native `pwncrash` 후속 행동을 제시하지 않는다.
  `rat-wasm verify`의 상태는 heuristic runtime observation으로 유지한다.

## 실행 검증

- `wasmtime==49.0.0`이 있는 native rev Python에서
  `tests.test_issue_112_runtime` **9개 통과**. WASI stdout 기대값
  `Correct!`의 일치와 `Other`의 불일치 control이 모두 실제로 실행됐다.
- 관련 결합 회귀 `unittest` **149개 통과** (`test_pkflag`,
  `test_ratbench_v2`, `test_newchal_canonical_route`, heap/GDB, decomp,
  route/feedback/schema, Wasm 포함).
- `AGENTS.md`의 `revq`, `rat`, `symsolve`, `vmlift`, `qiling_trace`,
  `k_kallsyms`, `ratbench`, `pklearn`, `pwngadget`, `pwnlibc` selftest와
  `tests.test_writeup_pipeline` 전부 GREEN.
- `python3 bin/ratbench run`: **11/11 route-correct**, verifier 2/11은
  Mode A에서 생성되지 않는 `rat-verify` 보고서 검사라 건너뜀.
  이 결과는 solve-rate 증거가 아니다.
- `bash tests/e2e_rev.sh` ALL GREEN; `bin/pkselftest` 23 PASS, 0 FAIL,
  0 SKIP.

## 남은 재현 범위

#104–#107의 실제 glibc 2.35 allocator 대상과 #112 원본 Snaky/PE/Wasm
artifact는 이 checkout에 없다. 모의 layout과 생성한 Wasm 모듈의 결과를
그 원본 대상 재현으로 표시하지 않는다. #114는 #113을 먼저 머지한 뒤
`dev`를 반영해 Router v2 결합 경로를 다시 검증하고 머지했다.
