# PR 리뷰 반영 및 순차 통합 작업 계획

작성일: 2026-10-17
대상 저장소: `b0nsu/CTF-Rat`
작업 순서: **#109 → #115 → #108 → #111 → #97 → #113 → #114**

## 목적과 작업 범위

이 문서는 다른 작업 세션이 일곱 PR의 리뷰를 반영하고, 지정된 순서로 통합·검증할 때 사용할 인수인계 문서다. 각 PR의 최신 HEAD와 리뷰 코멘트를 다시 확인한 뒤 작업한다. 이 문서의 HEAD 값은 작성 시점의 기준점이며, 변경된 경우 최신 코드에 맞춰 판단한다.

저장소 `AGENTS.md`의 운영 규칙을 따른다. 특히 **커밋과 푸시는 명시 요청이 있을 때만** 수행한다. 별도 지시가 없다면 변경과 테스트 결과를 검토 가능한 상태로 준비하고, 머지와 푸시는 수행하지 않는다.

| 순서 | PR | 브랜치 | 작성 시점 HEAD | 판단 |
| --- | --- | --- | --- | --- |
| 1 | [#109](https://github.com/b0nsu/CTF-Rat/pull/109) | `fix/99-pkflag-challenge-scope` | `4832274` | 코드 차단 사항 없음 |
| 2 | [#115](https://github.com/b0nsu/CTF-Rat/pull/115) | `review/ratbench-quoted-command` | `370f66d` | 머지 전 수정 필요 |
| 3 | [#108](https://github.com/b0nsu/CTF-Rat/pull/108) | `fix/issue-100-canonical-newchal-triage` | `35d504a` | 머지 전 수정 필요 |
| 4 | [#111](https://github.com/b0nsu/CTF-Rat/pull/111) | `fix/issues-104-107-heap-runtime-diagnostics` | `e82ba59` | 코드 차단 사항 없음; 실제 대상 재현은 후속 |
| 5 | [#97](https://github.com/b0nsu/CTF-Rat/pull/97) | `feat/issue-96-routing-feedback` | `95d9975` | 다음 실험 안내·흐름 검증 필요 |
| 6 | [#113](https://github.com/b0nsu/CTF-Rat/pull/113) | `review/issue-112-core` | `6e91c9f` | 코드 차단 사항 없음; 원본 artifact 재현은 후속 |
| 7 | [#114](https://github.com/b0nsu/CTF-Rat/pull/114) | `review/issue-112-runtime` | `038c39c` | #113 선행, 결합 회귀 및 native Wasmtime 검증 필요 |

작성 시점에 일곱 PR은 모두 열려 있다. #114의 base는 `review/issue-112-core`(#113)이고, 나머지 여섯 PR의 base는 `dev`다.

## 1. PR별 작업

### #109 — flag 형식의 challenge 범위

현재 HEAD는 challenge-local `FLAG_FORMAT`을 기본으로 사용하며, 형식 파일 symlink 읽기를 거부한다. 기존 리뷰의 코드 차단 사항은 해결된 것으로 확인됐다. 최신 HEAD에서 관련 테스트와 변경 사항을 재확인하고 순서상 첫 통합 대상으로 삼는다. `REAL`은 형식 일치일 뿐 flag 검증 증거가 아니라는 의미를 유지한다.

### #115 — 셸 명령 사전 검사 수정

`bin/ratbench`의 `cmd_eval`은 실행 시 `/bin/sh -c`를 사용하지만, 사전 검사에서 전체 명령을 `shlex.split()`한다. 셸에 유효한 중첩 명령 치환이 `shlex`에서 실패해 agent 실행 전에 종료 코드 2를 반환한다. 다음 사례는 `/bin/sh -c`에서 종료 코드 0, `shlex.split()`에서 `ValueError: No closing quotation`으로 재현됐다.

```python
cmd = r'''python3 -c 'print("ok")' "$(printf '"')"'''
```

- 실행 파일 확인에 필요한 부분만 검사하도록 수정하고 기존 `/bin/sh -c` 명령 계약을 유지한다.
- 회귀 테스트는 인용된 첫 실행 파일과 위 중첩 셸 구문을 모두 실제 셸 수준에서 실행한다.
- 정상 명령의 사전 검사·실행 성공과, 실행 파일 부재에 대한 기존 오류 처리를 확인한다.

관련 리뷰: [인라인 지적](https://github.com/b0nsu/CTF-Rat/pull/115#discussion_r4302535412).

### #108 — `newchal`의 저하된 route 감지

`rat.cmd_route`는 `revq` 예외를 `diagnostics: [{code: "analysis_failed", ...}]`로 기록하고도 종료 코드 0을 반환할 수 있다. 현재 `newchal`은 `rat route | tee`의 종료 코드만 보고 성공 안내를 출력한다. `set -o pipefail`은 비영 종료에는 유효하지만 이 사례를 구별하지 못한다.

- `rat route --format json` 등 구조화된 결과에서 `analysis_failed`를 검사하고, 해당 경우 명확한 `ROUTE UNKNOWN` 또는 저하된 triage 메시지를 남긴다. 출력은 `state.md`에도 보존한다.
- 일반적인 `provisional`·`unknown` 결과를 진단 코드 없이 무조건 실패로 분류하지 않는다.
- 기존 0/비영 종료 stub 테스트에 **종료 코드 0 + `analysis_failed`** 사례를 추가한다. PE 입력의 `--fast` 미사용 회귀도 유지한다.

관련 리뷰: [인라인 지적](https://github.com/b0nsu/CTF-Rat/pull/108#discussion_r4302535542).

### #111 — bounded heap 진단

GDB 메모리 읽기 timeout을 `partial`로 바꾸지 않고 `timeout`으로 전달하는 현재 HEAD의 수정은 확인됐다. 별도 코드 차단 사항이 없다면 순서대로 통합한다. `test_heap_snapshot_v21`은 모의 메모리 배치를 검증한다. 이 결과만으로 실제 glibc 2.35 heap 상태나 원래 SIGSEGV 원인을 재현했다고 표시하지 않는다. #104–#107의 실제 대상·allocator layout 검증은 후속으로 추적한다.

### #97 — 조회 뒤 다음 실험까지 이어지는 route

PWN capability card는 import·protection 사실이며 primitive 증거가 아니다. 현재 구현은 이 카드를 `partial`로 분류하고 동일 자동 조회를 다시 추천하지 않는다. 그 결과 lead와 `next`는 남지만 `decision=None`이 되어, 사용자가 선택할 callsite 조사나 runtime 실험이 route 출력에서 충분히 이어지지 않는다.

- `route → query pwn → route → 한 개의 대상 callsite 또는 runtime 실험`을 테스트·문서화한다.
- `next`에는 재조회 반복보다 `pwncrash`에 의한 control 측정 또는 bounded `decomp`에 의한 format/heap callsite·lifetime 조사처럼 선행 조건에 맞는 행동을 제시한다.
- 독립적인 사실 기반 lead가 경쟁하면 `decision=None`을 허용한다. 자동 refutation을 느슨하게 하거나 PWN 카드만으로 primitive PASS를 선언하지 않는다.
- `partial` PWN 카드 뒤의 `commitment`는 현재 `provisional`이며, 모든 첫 probe가 해결되고 남은 후보가 없을 때에는 `unknown`이 될 수 있다. 두 경우를 테스트에서 구별한다.

이 항목은 진행성·사용성 문제다. PR의 목표를 “active-triage closure”까지로 유지한다면 머지 전 완료 기준으로 다루고, 범위를 좁히기로 결정한다면 명시적인 후속 이슈와 사용자 안내를 남긴다.

관련 리뷰: [인라인 지적](https://github.com/b0nsu/CTF-Rat/pull/97#discussion_r4302537486).

### #113 — decomp 주소 및 실행 결과

관측된 Ghidra image base를 사용하는 주소 변환, `.rat-decomp-status.json`을 포함하는 캐시 payload seal, `rat-capture`의 자식 종료 코드 보존을 최신 HEAD에서 재확인한다. 이 PR을 #114보다 먼저 통합한다. 원본 Snaky/PE artifact는 현재 checkout에 없으므로 해당 사례의 재현 완료를 주장하지 않는다. 외부 셸 파이프라인이 `rat-capture`를 쓰지 않는 경우에는 별도로 `pipefail`·자식 종료 코드를 보존해야 한다.

### #114 — WASM route와 실행 진단

#113이 통합된 `dev`를 기준으로 #114를 재기반화·재검토한다. #97도 `bin/rat`와 `ratlib/route.py`를 수정하므로 두 변경이 함께 있을 때 다음을 검증한다.

- WASM route의 `signals`·`dimensions`·`next`가 Router v2 schema를 만족한다.
- #97의 probe ID·feedback이 WASM 경로를 손상시키지 않는다.
- `rat brief`가 결합된 route 정보를 정상 표시한다.
- 고정된 Wasmtime 환경에서 native 테스트를 실제 실행하고, 기대 stdout 일치와 불일치 입력을 모두 확인한다. 현재 시스템 Python에는 `wasmtime`이 없고, 기존 테스트는 `skipUnless`로 건너뛸 수 있다.
- `rat-wasm verify`의 기대 문자열 일치는 runtime 관측으로만 유지한다. challenge-specific oracle이나 primitive PASS·SOLVED 증거로 승격하지 않는다.

관련 리뷰: [인라인 지적](https://github.com/b0nsu/CTF-Rat/pull/114#discussion_r4302537715). 원본 WASM artifact·runner 통합 재현 전에는 #112를 완료 처리하지 않는다.

## 2. 통합과 검증 순서

1. 각 PR의 최신 HEAD, 리뷰 스레드, 상태를 다시 확인한다. 리뷰 이후 새 커밋이 있으면 해당 diff를 재검토한다.
2. #115·#108의 재현 사례를 먼저 실패 테스트로 고정하고 수정한다. #97의 진행성 기준을 위 항목대로 구현·검증한다.
3. 지정된 순서로 통합 결과를 준비한다. #113 뒤 #114를 갱신된 `dev`에 재기반화하고 최종 diff를 검토한다.
4. #97과 #114가 합쳐진 트리에서 route·brief·feedback 회귀를 실행한다. 두 브랜치의 `git merge-tree`에는 작성 시점 텍스트 충돌이 없었지만, 이는 결합 동작의 증거가 아니다.
5. 최종 결합 트리에서 `AGENTS.md`의 도구 전체 회귀검증을 모두 GREEN으로 만든다. `python3 bin/ratbench run`은 Mode A route 회귀이며 실제 solve-rate 증거로 해석하지 않는다. angr 환경이 있으면 `bash tests/e2e_rev.sh`도 실행한다.
6. PR별 테스트 결과와 건너뛴 검증을 구분해 기록한다. 작성 시점의 GitHub operational regression 통과와 `analysis-deep` 건너뜀은 최종 결합 트리 또는 native Wasmtime 검증을 대체하지 않는다.

## 완료 기준

- #115의 셸 명령 재현 사례와 #108의 종료 코드 0·`analysis_failed` 사례가 회귀 테스트에서 통과한다.
- #97의 PWN 카드 이후 다음 대상 실험이 제시되고, 기존 증거·primitive 게이트는 유지된다.
- #113 선행 후 #114의 최종 diff와 WASM·feedback·brief 결합 경로가 검증된다.
- 고정된 Wasmtime 환경에서 정상·실패 control이 모두 실행됐다는 결과가 남는다.
- 최종 결합 트리의 필수 회귀가 GREEN이다. 실제 대상 artifact가 없는 #104–#107 및 #112 재현은 후속 작업으로 명확히 남는다.
