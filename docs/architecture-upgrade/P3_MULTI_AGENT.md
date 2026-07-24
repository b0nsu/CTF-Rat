# P3 — 제한적 멀티에이전트와 phase gate

## 1. 목표와 비목표

### 목표

- 기존 6-phase 풀이 규약을 machine-checkable phase validator와 role contract로 만든다.
- fan-out을 불확실성이 실제로 존재하는 `solve-P2`에만, 최대 3개로 제한한다.
- task 시작/종료/fan-out/converge/invalidation에 checkpoint hook을 강제한다.
- invalidation을 발견하면 영향받는 task를 조기에 취소하고 그 사실을 STATE에 보존한다.
- exploit builder는 active verified primitive만 입력으로 받고, 최종 SOLVE 전에 skeptic이 반증을 시도한다.

### 비목표

- 문제 간 worker pool, queue, lease, stale reclaim, 자동 challenge 선택.
- peer-to-peer agent messaging을 진실원으로 사용하는 것.
- 무제한 토큰/시간/fan-out 또는 서로 다른 모델 결과의 다수결.
- exploit/flag 자동 제출과 사람 승인 없는 외부 write.

## 2. 선행조건과 완료 후 보장사항

### 선행조건

- [P2 완료 기준](P2_ANALYSIS_TOOLS.md#9-완료-기준)을 충족한다.
- `ctfguard` active challenge lock과 target allowlist가 GREEN이다.
- STATE v2 checkpoint/delta/invalidation과 primitive registry가 동작한다.
- agent가 반환할 schema와 resource/context budget을 task 시작 전에 고정할 수 있다.

### 완료 후 보장사항

- 모든 task가 어떤 solve phase, role, input cursor, budget에서 실행됐는지 재구성할 수 있다.
- 금지 phase의 fan-out과 상한 초과 fan-out은 spawn 전에 거부된다.
- invalidated evidence를 사용 중인 task와 exploit build는 진행하지 못한다.
- agent가 죽거나 schema-invalid 결과를 내도 raw 대화에 의존하지 않고 checkpoint에서 이어갈 수 있다.
- skeptic PASS와 concrete verification 없이는 verified solve를 선언할 수 없다.

## 3. PDF 백로그 ID 매핑

| ID | 작업 | 구현 결과 |
|---|---|---|
| B022 | phase validator | solve phase 전이·fan-out·primitive gate 검증 |
| B023 | role contract | 입력/출력/권한/context budget이 typed된 역할 |
| B024 | fan-out trigger | 불확실성 기반 spawn과 최대 3개 제한 |
| B025 | early cancellation | invalidation 영향 분석, cancel, converge 기록 |
| B026 | skeptic gate | adversarial verify report 없이는 solve 거부 |

## 4. 구현 작업 단위와 내부 의존성

```text
B022 phase validator ── B023 role contract ── B024 fan-out
          │                      │                   │
          └──────────────────────┴──── B025 cancellation
                                                   │
                                  primitive registry ── B026 skeptic gate
```

### P3.1 — B022 phase validator

upgrade 단계 P0~P4와 구분하기 위해 실행 state에는 `solve-P0`~`solve-P5`를 쓴다.

| solve phase | 주체 | fan-out 규칙 | 진입 gate | 종료 gate |
|---|---|---|---|---|
| `solve-P0` Triage | orchestrator | **금지** | active guard, profile input | profile facts/signals/routes + solvability checkpoint |
| `solve-P1` RE/정찰 | scout 위임 | 병렬 가설 fan-out 아님; 큰 읽기만 위임 | bounded read target | artifact/finding delta와 coverage |
| `solve-P2` Vuln 가설 | hypothesis | 불확실할 때만 **최대 3개** | 서로 배타적 후보와 budget | converge report, retained/refuted 후보 |
| `solve-P3` Primitive | primitive verifier/오케스트레이터 | **금지** | selected finding | SELF 결과와 primitive registry revision |
| `solve-P4` Exploit 체이닝 | exploit builder 1개 | **금지** | compatible active primitive PASS | local/remote-equivalent concrete result |
| `solve-P5` Verify | skeptic **정확히 1개** | 반증 역할 1개만 | exploit artifact + evidence graph | refute/accept report와 terminal checkpoint |

허용 전이는 기본적으로 순방향 한 단계다. invalidation 때문에 뒤로 갈 때는 `phase.rollback` event에 target phase,
원인 evidence, stale 처리된 finding/primitive를 기록한다. `solve-P3→solve-P4`는 active PASS가 없으면 거부하고,
`solve-P5→complete`는 skeptic과 executable oracle 둘 중 하나라도 inconclusive면 거부한다.

checkpoint hook:

| 시점 | reason | 필수 내용 |
|---|---|---|
| task 시작 전 | `task-start` | input cursor, role contract, budget, 허용 artifact/finding |
| task 종료 | `task-end` | result envelope, output cursor, consumed budget, status |
| fan-out 직전 | `fan-out` | trigger evidence, branch hypothesis, 최대 수 |
| fan-out 수렴 | `converge` | retained/refuted/unknown branch와 선택 근거 |
| invalidation 즉시 | `invalidation` | invalid event, dependency impact, cancel 대상 |
| phase 전환 | `phase-exit`/`phase-enter` | validator report와 next cursor |

### P3.2 — B023 role contract

모든 role contract(`rat.role-contract/v1`)는 role, solve phase, objective, allowed inputs, required outputs,
forbidden actions, state write scope, tool/network/file capability, context/tool-call/wall budget, stop conditions를 가진다.

| 역할 | 허용 입력 | 필수 출력 | 금지 사항 |
|---|---|---|---|
| orchestrator | run/checkpoint 전체 summary | phase/dispatch/converge/rollback event | 문제 간 dispatch, 검증 없는 승격 |
| scout | 지정 artifact와 함수/주소 locator, cursor delta | observation/finding 또는 명시적 no-result, coverage | 전체 raw dump, exploit chain 작성 |
| hypothesis | 공통 facts + 자기 branch 가설 | supported/refuted/unknown finding과 evidence | 다른 branch 수정, primitive PASS |
| primitive verifier | selected finding, scenario, evidence refs | verification report와 primitive candidate/revision | hypothesis만으로 chain 작성 |
| exploit builder | **active PASS primitive만** | exploit artifact, constraints, concrete run result | stale/blocked/candidate primitive, 새 가설 fan-out |
| skeptic | exploit/result/evidence graph의 read-only view | 반증 case, verdict, residual risk | exploit 수정, evidence 승격, 두 번째 skeptic spawn |

기본 context budget은 task당 input 12,000 token, output 4,000 token, inline artifact summary 총 32 KiB다.
초과 데이터는 digest+locator로만 전달한다. backend가 token 사용량을 제공하지 않으면 UTF-8 byte/4 추정치와
`estimated=true`를 기록한다. challenge policy가 값을 바꿀 수 있지만 무제한 값은 허용하지 않는다.

schema-invalid agent output은 raw response를 `quarantined-agent-output` artifact로 저장하고 STATE에 merge하지
않는다. validator diagnostic을 붙여 같은 role에 **한 번만** repair 요청한다. 다시 실패하면 task를
`cancelled:invalid-output`으로 끝내고 orchestrator가 takeover 또는 새 checkpoint에서 재시작한다.

### P3.3 — B024 fan-out trigger

`solve-P2` fan-out은 다음 조건을 모두 만족할 때만 허용한다.

1. profile/slice/dyn 근거가 서로 배타적인 vuln class 또는 원인 후보를 2개 이상 남겼다.
2. 각 branch가 독립적인 좁은 objective와 falsification condition을 가진다.
3. 같은 artifact를 다시 읽는 중복 작업이 아니며 cache/delta로 입력을 공유할 수 있다.
4. 남은 전체 budget이 branch별 최소 budget과 converge budget의 합보다 크다.
5. active branch 수가 3개를 넘지 않는다.

trigger는 `uncertainty_set`, 후보별 evidence, 예상 비용, 중단 조건을 기록한다. 후보가 하나면 fan-out하지 않고
순차 실행한다. 4개 이상이면 profile/slice로 먼저 좁히고 상위 3개를 단순 점수로 잘라 spawn하지 않는다.

`solve-P1`의 여러 scout는 context-heavy 읽기 위임이며 hypothesis fan-out quota에 포함하지 않지만, 각 scout도
서로 다른 artifact/locator를 가져야 하고 동시 실행 수는 policy cap 3을 넘지 않는다.

### P3.4 — B025 early cancellation과 converge

- orchestrator는 새 `alert`/`evidence.invalidated` event마다 active task의 input evidence dependency를 조회한다.
- 영향 task에는 cancellation token을 보내고 P0 runner가 TERM→KILL로 child를 정리한다.
- 취소 전후 checkpoint에 `requested_at`, `acknowledged_at`, `forced_at`, reason event, 보존한 partial artifact,
  사용 budget을 기록한다.
- 같은 dead-end를 따르는 sibling은 함께 취소한다. 영향이 없는 branch는 계속 실행할 수 있다.
- 취소된 결과가 늦게 도착하면 artifact는 보존하되 finding/state merge는 거부하고 `late_after_invalidation`으로 표시한다.
- converge는 모든 branch의 terminal/cancelled status를 기다리거나 stop-loss에 도달하면 실행한다. unknown을 승자로
  고르지 않으며 선택 근거를 finding evidence로 남긴다.

stop-loss:

- easy-tier 전체 목표는 기존 doctrine대로 20분이다. 각 task는 더 작은 wall/tool-call budget을 가져야 한다.
- progress는 새 direct observation, finding 전이, primitive evidence, 명시적 route refutation 중 하나다.
- 연속 두 checkpoint 동안 progress가 없거나 context/tool-call/wall budget 중 하나가 소진되면 stop-loss다.
- hard challenge도 개별 task budget은 유한하다. 대회 전체 조사 시간이 길 수 있다는 것이 한 task의 무제한 실행을
  뜻하지 않는다.
- stop-loss 후 기본 동작은 orchestrator takeover 또는 blocked handoff이며 자동 fan-out 증가는 금지한다.

### P3.5 — B026 skeptic gate

`solve-P5` skeptic은 exploit을 고치는 역할이 아니라 반증하는 read-only 역할이다. 최소 점검:

- leak이 controlled marker(`0x4c...`, `0x47...`)나 safe-linking key를 실제 pointer로 오인하지 않았는가.
- binary/libc/loader/rootfs hash와 exploit 가정이 일치하는가.
- gdb/core 전용 주소, `/proc/maps`, 고정 ASLR, argv/env layout에 의존하지 않는가.
- terminator, short read/write, reconnect, timing, allocator state가 최소 payload와 같은가.
- local 결과가 remote-equivalent라고 주장할 evidence가 있는가.
- 원격 반복 brute-force 없이 deterministic하게 성립하는가.

skeptic output(`rat.skeptic-report/v1`)은 verdict `accept`, `refute`, `inconclusive`, 실행한 counterexample,
영향 evidence/finding/primitive, residual risks를 포함한다. `accept`도 SOLVE를 직접 선언하지 않는다. phase validator가
active primitive, concrete verification, skeptic report, target provenance를 함께 확인한 뒤에만 verified 상태를 만든다.

## 5. CLI·schema·파일 레이아웃 변경

```text
rat-phase status|enter|exit|rollback ...
rat-task start --contract FILE --checkpoint ID [--child-pid PGID]
rat-task finish|repair|cancel|invalidate ...
rat-fanout plan --branches FILE --trigger FILE --budget FILE | converge ...
rat-skeptic --file REPORT.json
```

```text
schemas/rat.role-contract.v1.json
schemas/rat.task-event.v1.json
schemas/rat.converge-report.v1.json
schemas/rat.skeptic-report.v1.json
bin/ratlib/orchestration/{phase,roles,fanout,cancel,skeptic}.py
tests/fixtures/orchestration/
```

오케스트레이터 구현은 agent vendor transport를 schema 밖으로 격리한다. STATE/artifact 계약은 특정 agent API를
알지 못하며, transport가 없어도 single-agent mode에서 phase validator와 skeptic 수동 실행이 가능해야 한다.

## 6. 하위 호환성 및 migration

- 기존 [`doctrine/SOLVING.md`](../../doctrine/SOLVING.md)의 표와 명령은 유지하고 `rat-phase`를 검증 보조로
  추가한다. 기존 phase 명칭은 UI에서 그대로 보이되 저장값은 `solve-P*`다.
- STATE v1 작업은 P1 migration 후 orchestration에 참여한다. migration 전에는 advisory-only mode로 phase를
  표시하지만 자동 spawn/solve 승격을 금지한다.
- subagent가 없는 환경은 role을 순차 실행한다. fan-out 없는 것이 오류는 아니며 동일 checkpoint hook을 사용한다.
- 기존 `primitives.py`는 registry PASS에서 생성한 compatibility facade를 import할 수 있다. 수동 함수는 provenance가
  없으면 candidate로만 인식한다.

## 7. 실패 모드와 보안 조건

| 실패 모드 | 요구 동작 |
|---|---|
| 금지 phase fan-out | spawn 전 code 5, policy diagnostic |
| branch 4개 이상 | profile/slice로 재수렴; quota 우회 금지 |
| context budget 초과 | artifact reference로 축약 또는 stop-loss |
| schema-invalid output | quarantine, 1회 repair, 재실패 시 cancel |
| agent/transport 사망 | 마지막 checkpoint와 partial artifact에서 재개 |
| invalidation 중 실행 | 영향 task 조기 취소, 늦은 output merge 금지 |
| primitive evidence 부족 | `solve-P4` 진입과 exploit builder 호출 거부 |
| skeptic inconclusive/refute | verified solve 거부, rollback/blocked 기록 |
| target/ROE 불일치 | agent tool 권한과 subprocess 모두 fail closed |
| secret in prompt/output | 저장/전달 전 redaction 실패 시 task 중단 |

role은 최소 권한만 가진다. scout/hypothesis/skeptic에는 network write와 repository write를 주지 않는다. exploit
builder도 지정 challenge target 외 네트워크 접근을 얻지 못한다. flag 제출 capability는 어떤 role에도 없다.

## 8. 테스트 fixture와 실행 명령

필수 fixture:

- 각 solve phase의 정상/불법 전이와 rollback.
- `solve-P0/P3/P4` fan-out 요청, `solve-P2` 1/2/3/4 branch, `solve-P5` 0/1/2 skeptic.
- 서로 다른 locator의 P1 scout와 중복 raw-read scout.
- active/blocked/stale/wrong-environment primitive로 exploit builder 호출.
- branch가 invalidation을 만들고 sibling이 TERM 수락/무시/late output을 반환하는 경우.
- token/context/tool-call/wall budget 각각의 stop-loss.
- invalid JSON, valid JSON/wrong schema, oversized output, repair 성공/실패 agent.
- skeptic accept/refute/inconclusive와 false leak/libc mismatch/local-only exploit.

구현 후 실행 명령:

```sh
python3 -m unittest tests.test_phase_validator tests.test_role_contract
python3 -m unittest tests.test_fanout tests.test_early_cancel tests.test_skeptic_gate
python3 tests/e2e_orchestration.py --scenario converge
python3 tests/e2e_orchestration.py --scenario invalidate-cancel
python3 tests/e2e_orchestration.py --scenario verified-only-exploit
python3 tests/e2e_orchestration.py --scenario skeptic-refute
```

e2e는 fake deterministic agent transport와 실제 subprocess child를 모두 사용해 event 순서와 orphan 부재를
검사한다.

## 9. 완료 기준

- [x] phase validator가 허용 전이와 invalidation rollback을 재현 가능하게 판정한다.
- [x] `solve-P0`, `solve-P3`, `solve-P4` fan-out이 항상 거부된다.
- [x] `solve-P1`은 bounded read 위임만, `solve-P2`는 trigger 충족 시 최대 3개만 허용된다.
- [x] `solve-P5`에는 read-only skeptic 정확히 1개가 실행된다.
- [x] task start/end/fan-out/converge/invalidation checkpoint hook이 누락될 수 없다.
- [x] invalidation의 영향 task가 조기 취소되고 late output이 state에 merge되지 않는다.
- [x] context budget과 stop-loss가 무제한 task를 허용하지 않는다.
- [x] schema-invalid output이 quarantine되고 1회 repair 후 fail closed한다.
- [x] exploit builder가 active/compatible primitive PASS 외 모든 입력을 거부한다.
- [x] skeptic refute/inconclusive에서 verified solve가 거부된다.
- [x] single-agent fallback도 같은 phase/evidence gate를 지킨다.

## 10. 권장 커밋 분할

1. `feat: validate solve phases and checkpoint hooks`
2. `feat: define bounded agent role contracts`
3. `feat: gate hypothesis fan-out by uncertainty and budget`
4. `feat: cancel tasks affected by evidence invalidation`
5. `feat: converge branches with durable cancellation records`
6. `feat: require adversarial skeptic before verified solve`
7. `test: exercise invalid output budgets and verified-only exploit input`
8. `docs: align multi-agent doctrine with enforced gates`

## 11. 진행 체크리스트

- [x] B022 phase validator/hooks
- [x] B023 role contracts/budgets
- [x] B024 fan-out trigger/cap
- [x] B025 cancellation/converge
- [x] B026 skeptic gate
- [x] single-agent fallback
- [x] orchestration e2e
- [x] [완료 기준](#9-완료-기준) 전체 확인 — P2 선행 완료 및 full regression 통과
