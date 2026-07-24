# ctf-rat architecture upgrade

이 디렉터리는 PDF 백로그 B001~B030을 구현 가능한 단위로 고정한 단계별 설계 문서다. 기존
[`RUNNER_ARCHITECTURE.md`](../../RUNNER_ARCHITECTURE.md)의 "한 문제 집중" 원칙과
[`doctrine/SOLVING.md`](../../doctrine/SOLVING.md)의 ROE·6-phase 절차를 바꾸지 않고, 그 위에
안전한 실행 계층, 데이터 계약, 분석 도구, 제한적 멀티에이전트, 측정 계층을 순서대로 추가한다.

이 문서에서 **P0~P4**는 업그레이드 구현 단계를 뜻한다. 실제 풀이 phase는 혼동을 막기 위해
`solve-P0`(Triage)~`solve-P5`(Verify)로 표기한다.

## 전체 아키텍처

```text
challenge input
      │
      ▼
P0 safe ingest + bounded subprocess + trustworthy manifest
      │  rat.run/v1 초안, 안정적인 종료/timeout
      ▼
P1 tool-result envelope + immutable artifact store + STATE v2
      │  observation/finding/primitive/checkpoint 참조
      ▼
P2 rat-profile → rat-slice / rat-dyn → rat-verify
      │             └─ heap / ROP / runtime / VM 확장
      ▼
P3 phase validator + bounded roles/fan-out + skeptic gate
      │
      ▼
P4 40-challenge corpus + KPI + ablation + nightly regression
```

의존성은 **P0 → P1 → P2 → P3 → P4**로 고정한다. 뒤 단계의 프로토타입을 먼저 만들 수는
있지만, 앞 단계의 완료 기준을 통과하기 전에는 뒤 단계를 `complete`로 바꾸거나 기본 경로에
활성화하지 않는다.

## 공통 원칙

- **ROE 우선:** 네트워크 실행은 `ctfguard`의 활성 문제와 target allowlist를 통과해야 한다.
- **honest-mode:** flag 자동 제출과 검증 없는 SOLVE 선언을 구현하지 않는다.
- **fact / hypothesis / primitive 분리:** heuristic은 signal 또는 hypothesis이며 fact가 아니다.
  exploit chaining은 유효한 primitive PASS만 입력으로 받는다.
- **artifact-first handoff:** raw stdout을 프롬프트나 상태 버스에 복사하지 않는다. immutable artifact와
  observation/finding ID로 인계한다.
- **결정론적 재현:** 입력 hash, 도구·의존성 버전, 실행 정책을 기록한다. cache key에 포함되지 않은
  환경 차이는 provenance에 남긴다.
- **부분 결과 보존:** timeout이나 선택적 dependency 부재를 성공으로 위장하지 않는다. 확보한 결과는
  `partial`로 보존하고 누락 범위와 재시도 조건을 함께 기록한다.
- **fail closed:** archive 경로, target, schema, primitive evidence가 불명확하면 다음 단계로 넘기지 않는다.
- **기존 사용자 보호:** 기존 텍스트 CLI와 STATE v1은 읽을 수 있어야 한다. 새 구조화 출력은 명시적
  옵션 또는 새 `rat-*` 명령부터 도입한다.
- **single active challenge:** 문제 간 queue, lease, worker scheduler를 만들지 않는다.

## 단계 의존성과 진행 현황

허용 상태는 `planned`, `in-progress`, `blocked`, `complete` 네 가지뿐이다. 상태 변경 PR은 해당
단계 문서의 체크리스트와 근거 artifact를 함께 갱신한다.

| 단계 | 상태 | 범위 | 선행 단계 | 완료 기준 |
|---|---|---|---|---|
| [P0](P0_STABILITY.md) | `complete` | 안정성·코드/문서 정합성, B001~B007 | 현재 도구 checkpoint | [P0 완료 기준](P0_STABILITY.md#9-완료-기준) · [검증 기록](P0_VERIFICATION.md) |
| [P1](P1_DATA_CONTRACTS.md) | `implemented` | schema, artifact store, STATE v2, B008~B013 | P0 | [P1 완료 기준](P1_DATA_CONTRACTS.md#9-완료-기준) |
| [P2](P2_ANALYSIS_TOOLS.md) | `implemented` | 분석 정확도와 `rat-*`, B014~B021 | P1 | [P2 완료 기준](P2_ANALYSIS_TOOLS.md#9-완료-기준) |
| [P3](P3_MULTI_AGENT.md) | `complete` | 제한적 멀티에이전트와 phase gate, B022~B026 | P2 | [P3 완료 기준](P3_MULTI_AGENT.md#9-완료-기준) |
| [P4](P4_BENCHMARK.md) | `in-progress` | corpus, KPI, ablation, regression, B027~B030 | P3 | [P4 완료 기준](P4_BENCHMARK.md#9-완료-기준) |

상태 변경 규칙:

1. 구현 branch가 열리고 담당자·첫 검증 명령이 기록되면 `in-progress`로 바꾼다.
2. 외부 입력이나 선행 단계 없이는 진행할 수 없을 때만 `blocked`로 바꾸고 blocker를 표 아래에 적는다.
3. 링크된 완료 기준이 모두 충족되고 근거가 CI artifact에 남았을 때만 `complete`로 바꾼다.
4. 회귀로 보장이 깨지면 즉시 `in-progress` 또는 `blocked`로 되돌린다.

## 공통 저장 경계

신규 런타임 데이터는 challenge 디렉터리의 `.rat/` 아래에만 둔다. git에는 schema, 작은 fixture,
benchmark manifest만 추적하고 실제 바이너리, stdout, core, cache, secret은 추적하지 않는다.

```text
<challenge>/.rat/
├── run.json
├── events/STATE.v2.jsonl
├── objects/sha256/<prefix>/<digest>
├── checkpoints/
├── indexes/
├── locks/
└── tmp/
```

정확한 데이터 계약과 ignore 경계는 [P1](P1_DATA_CONTRACTS.md)에 정의한다.

## 명시적 제외 범위

전체 계획에서 다음은 구현하지 않는다.

- **flag 자동 제출:** flag 검출·형식 확인까지만 자동화하며 제출은 사람이 한다.
- **문제 간 queue/자동 배분:** 한 번에 활성 문제 하나라는 lock을 유지한다.
- **무제한 fan-out:** `solve-P2`에서도 최대 3개, `solve-P5`는 skeptic 1개뿐이다.
- **프로세스 snapshot/replay:** 실행 입력·환경·artifact는 기록하지만 프로세스 메모리 snapshot을 복원해
  replay하는 시스템은 만들지 않는다.

## Draft PR 체크리스트

- [ ] PR 설명에 대상 backlog ID와 단계 상태 변경을 적었다.
- [ ] 기존 dirty worktree와 분리된 도구 전용 checkpoint에서 시작했다.
- [ ] [P0 완료 기준](P0_STABILITY.md#9-완료-기준)을 직접 확인했다.
- [ ] [P1 완료 기준](P1_DATA_CONTRACTS.md#9-완료-기준)을 직접 확인했다.
- [ ] [P2 완료 기준](P2_ANALYSIS_TOOLS.md#9-완료-기준)을 직접 확인했다.
- [ ] [P3 완료 기준](P3_MULTI_AGENT.md#9-완료-기준)을 직접 확인했다.
- [ ] [P4 완료 기준](P4_BENCHMARK.md#9-완료-기준)을 직접 확인했다.
- [ ] schema/CLI 변경에는 fixture, migration note, 실패 예가 포함돼 있다.
- [ ] CI 로그나 `.rat` object 자체가 아니라 digest와 요약을 검증 근거로 링크했다.
- [ ] flag 자동 제출, 문제 간 queue, 허용치 초과 fan-out, snapshot/replay가 추가되지 않았다.
- [ ] 커밋과 push는 사람의 명시 요청 범위에서만 수행했다.
