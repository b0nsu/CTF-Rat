# 로컬 분석 기록·인계 양식

> 이 문서는 CTF-RAT의 canonical 내부 기록 양식이다. `PRIMITIVE_PASS`는 로컬에서
> primitive를 검증했다는 뜻이며 `SOLVED`·flag 획득·제출 완료와 동의어가 아니다.
> 검증하지 않은 내용은 사실처럼 쓰지 않는다.

## 문서 상태

다음 상태 중 하나만 사용한다.

| 상태 | 의미 |
|---|---|
| `ANALYZING` | 사실과 가설을 수집하고 있음 |
| `PRIMITIVE_PASS` | 최소 입력으로 primitive를 로컬 검증함 |
| `BLOCKED` | 검증되지 않은 가설 또는 명시된 차단 조건이 남음 |
| `OPERATOR_COMPLETED` | 사람이 후속 작업과 결과를 별도로 확인함 |

`pkshare`의 기본 출력은 `HANDOFF.md`다. `WRITEUP.md`와 `SUBMISSION.md`는 운영자가
서명한 구조화 attestation을 각각 `--solved --attestation <json>` 또는
`--submission --attestation <json>`으로 제공한 경우에만 생성한다. 기존 문서는
기본적으로 덮어쓰지 않으며, 기계 생성본을 의도적으로 재생성할 때만 `--force`를 쓴다.

## 상태 신뢰 원본

- `.rat/events/STATE.v2.jsonl`이 있으면 materialized v2 view만 authoritative하다.
- v2 evidence invalidation으로 `stale`이 된 primitive를 문서에서 PASS로 표시하지 않는다.
- legacy `STATE.jsonl`의 PASS 문구는 migration 후 직접 증거를 다시 연결하기 전까지
  candidate로만 표시한다.
- v2 PASS라도 입력·환경 digest, 서로 다른 3개 이상의 active direct SELF evidence,
  재현 명령, marker 증거가 빠졌거나 evidence object의 hash 재검증이 실패하면 문서
  상태를 `PRIMITIVE_PASS`로 승격하지 않는다.

## 운영자 Attestation

완료 문서에는 다음 구조의 JSON이 필요하다. `evidence` digest는 현재 artifact 또는 v2
observation에서 실제로 참조 가능한 값이어야 한다.

```json
{
  "schema": "rat.writeup-attestation/v1",
  "operator": "<operator identity>",
  "confirmed_at": "2026-08-11T12:00:00+09:00",
  "result": "<independently confirmed result>",
  "evidence": ["sha256:<64 hex characters>"]
}
```

````md
# <문제명> — <상태>

## 상태와 범위

- 문서 유형: <handoff / writeup / submission>
- 상태: <ANALYZING / PRIMITIVE_PASS / BLOCKED / OPERATOR_COMPLETED>
- 검증 범위: <로컬 process / Docker / loopback>
- 로컬 flag 검증: <수행하지 않음 / 의도된 challenge flag를 로컬에서 확인; 대상·실행 조건·환경 digest>
- 외부 결과·제출: <수행하지 않음 / 운영자 확인>

## Artifact와 환경

- OS / 아키텍처:
- 제공 파일과 SHA-256:
- primitive 최소 입력 SHA-256:
- libc / loader SHA-256 및 build-id:
- Docker image 또는 환경 digest:
- 분석·재현 도구와 버전:

## 핵심 요약

- 확인된 사실:
- 검증된 primitive:
- 활성 가설:
- 검증하지 않은 주장:

## 풀이과정

1. <관측한 사실과 근거>
2. <가설과 이를 검증하거나 배제한 실험>
3. <결과와 다음 판단>

## Gate Status

- primitive: <PASS / BLOCKED / NOT STARTED>
- 최소 입력:
- 실행 명령:
- register / core / marker 증거:
- terminator / length 부작용:
- ASLR / argv / env / layout 의존성:
- 증거 파일:

## 재현

```text
<제공된 artifact부터 primitive 관측까지의 로컬 명령>
```

- 예상 관측:
- 실패 조건:

## 배제된 경로

- <경로와 재시도하지 않을 근거>

## 제약과 운영자 인계

- 남은 체이닝 조건:
- 사람이 확인해야 하는 내용:
- 자동화 범위 밖 작업:

## 재사용 가능한 지식

- 일반화된 패턴:
- 적용 전제조건:
- 통하지 않는 조건 또는 반례:
- 다음 문제에서의 최소 확인 절차:
- 승격 상태: <candidate / validated / reused>

## AI·자동화 사용

- 사용 여부:
- 사용 도구:
- 사용 범위:
- 사람이 재검증한 내용:
````

## 작성 규칙

- STATE subsystem을 사실·가설·배제·primitive 판정의 단일 사실원으로 사용한다.
- typed v2 stream이 존재하면 legacy 로그보다 우선하며 invalidation을 materialize한다.
- 명령어·코드·입력은 실제로 사용한 로컬 재현본만 기록한다.
- PASS에는 입력 및 환경 digest, 실행 명령, marker를 포함한 직접 증거를 연결한다.
- 스크린샷과 dump에는 파일 경로, 생성 조건, 대상 digest를 함께 남긴다.
- 의도된 로컬 challenge flag 확인은 재현 증거로 기록할 수 있으나, `PRIMITIVE_PASS` 문서에서 외부 flag 획득이나 제출 완료를 암시하지 않는다.
- AI·자동화가 한 일과 사람이 검토·검증한 범위를 분리한다.
- 문제 하나에서 얻은 교훈은 `candidate`로 시작한다. 독립 artifact 재현 또는 반례
  검토 후 `validated`, 다른 문제에서 실제 재사용한 뒤 `reused`로 승격한다.

## 외부 제출본

외부 제출본은 내부 인계물과 분리한다. 운영자가 최종 결과를 확인한 뒤에만
`pkshare --submission --attestation <json>` 또는 별도 검토로 `SUBMISSION.md`를 만들며, 대회 메타데이터,
하나의 완결된 풀이 경로, 실제 결과를 포함할지는 운영자가 결정한다.
