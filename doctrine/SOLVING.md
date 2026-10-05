# 로컬 CTF artifact 분석·재현 규약

> **DEEP 전용 문서.** CLAUDE.md FAST hot-path에서는 로드하지 않는다. DEEP 승격 조건(모호한 결과·env-민감·
> 같은 실패 반복·evidence 충돌·Progress Novelty Governor stuck) 충족 시, 또는 사용자가 명시적으로 요청할 때만 읽는다.

## 범위

- 제공된 바이너리·소스·libc·Docker·loopback 환경만 분석하고 실행한다.
- 제공 artifact·challenge 디렉터리·로컬 Docker/loopback에서 challenge가 의도적으로 노출하는 flag는 end-to-end 로컬 재현 증거로 읽을 수 있다. 이는 외부 결과 획득이나 제출 완료를 뜻하지 않는다.
- 외부 호스트·포트·계정·대회 인프라와의 접속, 스캔, 결과 획득 및 제출은 이 규약의 범위 밖이다. 사용자 홈·SSH 키·토큰·환경변수 등 실제 자격증명 탐색도 금지한다.
- 요청이 거부되었거나 범위가 불명확하면 표현 변경, 작업 분할, 하위 에이전트로 재시도하지 않는다. 로컬 분석 결과만 기록한다.

## 미션

userland x86-64 Linux pwn/rev artifact에서 FAST가 이미 수집한 증거를 버리지 않고 이어받아,
경쟁하는 가설이나 환경 의존성을 **최소한의 추가 실험으로 수렴**시키고 취약점 또는 검증 로직을
로컬에서 재현 가능한 증거와 최소 PoC로 정리한다. 완료 기준은 외부 결과가 아니라
**로컬에서 재현되는 분석 결론**이다.

## DEEP 진입 계약

DEEP는 새 풀이 세션이 아니라 **현재 FAST working set의 확장 모드**다.

- active challenge lock, artifact, cache/index, typed STATE v2, 현재 route 결과, 이미 수행한 bounded query와 실패 기록을 그대로 이어받는다.
- `newchal`, `recon`, 전체 `revq`, 전체 decompile을 DEEP 진입 의식처럼 다시 실행하지 않는다.
- 먼저 `rat state compact --budget-tokens N`으로 현재 typed evidence/hypothesis/primitive/ruled-out/next를 bounded하게 복원한다.
- 현재 route 결과가 working context에 없거나 artifact/evidence가 바뀌어 명백히 stale인 경우에만 `rat route <bin>`을 한 번 다시 실행한다.
- 필요한 capability가 이미 cache/artifact에 있으면 재계산하지 않고 bounded query로 조회한다.
- FAST에서 확인된 Skill이 있으면 그대로 유지한다. 새 evidence가 기존 Skill을 반증할 때만 route 근거를 다시 평가한다.
- primitive PASS, verification, invalidation 같은 trust state는 prompt 기억이 아니라 typed STATE와 deterministic gate가 최종 권위다.

```text
current FAST evidence
+ compact STATE
+ cached deterministic artifacts
        ↓
conflicts / unresolved premises
        ↓
bounded competing branches (<=3)
        ↓
one discriminating experiment
        ↓
evidence update / falsification
        ↓
converge
        ↓
primitive proof
        ↓
deterministic verification
```

## 증거 수렴 루프

### 1. 현재 evidence snapshot

현재 working set에서 active direct/derived observation, confirmed/supported finding, active primitive, unresolved premise, ruled-out route, classified failure, 최근 실패의 반증 내용, 현재 route의 coexisting leads/commitment/Skill, 환경 의존성만 추린다.

전체 STATE JSONL이나 raw decompile dump를 모델 context에 넣지 않는다. 필요한 함수·xref·slice는 `rat query func|oracle|pwn|pattern|slice` 또는 함수 단위 `decomp`로 조회한다.

### 2. 경쟁 branch를 최대 3개로 제한

DEEP가 필요한 이유가 되는 **서로 독립적인 설명**만 branch로 만든다. 각 branch는 claim, missing premise, discriminator, expected evidence, falsifier, cost/side effect를 가져야 한다. 같은 분석을 이름만 바꿔 fan-out하지 않으며 branch가 하나면 fan-out하지 않는다.

### 3. 한 번에 discriminator 하나만 실행

가장 저비용이며 branch를 가장 많이 줄이는 실험 하나를 선택한다. stack/ROP control 후보는 bounded runtime 측정, format/heap 후보는 bounded callsite/lifetime 확인, checker/rev 후보는 함수/oracle 확인, packing·anti-debug·환경 후보는 blocker 전제 확인, VM 후보는 dispatch loop/bytecode semantics 확인을 우선한다.

실험 결과는 observation/finding/ruled-out/failure로 즉시 STATE에 남긴다. 결과가 기존 route 가정이나 Skill을 깨지 않는다면 전체 route/recon을 다시 돌리지 않는다.

### 4. 수렴 또는 stop-loss

- falsified branch는 `state route` 또는 typed finding revision으로 닫는다.
- 새 direct/derived evidence가 생긴 branch만 유지하고 동일 실패를 반복하지 않는다.
- 최근 5회 tool/query에서 novelty가 없으면 Progress Novelty Governor의 stuck을 존중해 branch 정의를 바꾸거나 blocker를 기록하고 stop-loss 한다.
- branch 수가 늘어나면 가장 약한 branch를 버려 다시 3개 이하로 줄인다.

### 5. 필요한 지식만 lazy-load

현재 missing premise를 푸는 데 개념 지식이 실제로 필요한 경우에만 `knowledge/GROUNDING_INDEX.md`에서 관련 자료 하나를 선택한다. 지식은 hypothesis aid일 뿐 observation이나 primitive 증거를 대체하지 않으며 doctrine 전체나 여러 Skill을 preload하지 않는다.

### 6. primitive proof 이후에만 chain

후보는 `state hypothesis` 또는 candidate primitive로 남긴다. `doctrine/PRIMITIVE_GATE.md`의 SELF 조건을 통과하기 전에는 exploit/solve chain을 완성된 것으로 취급하지 않는다.

primitive PASS 뒤에만 chain을 최소화하고 `solve_local.py` 또는 최소 PoC를 local process/Docker/loopback에서 실행한 뒤 `rat-verify` 또는 해당 deterministic verifier로 검증한다. verifier가 명확하면 별도 LLM skeptic은 의무가 아니다. 환경 민감성·증거 충돌·복수 해석이 남아 있을 때만 skeptic/독립 재현을 추가한다.

### 7. 결과 기록

검증된 로컬 재현 절차와 한계를 typed STATE v2 stream 및 선택적 writeup에 남긴다. 로컬 flag를 읽은 경우 대상·실행 조건·환경 digest를 함께 기록한다.

## 재현성 규칙

> 재현성·확률 경로 금지의 **단일 출처는 [doctrine/PRIMITIVE_GATE.md](PRIMITIVE_GATE.md)의 "재현성 규칙" 절**이다. 아래는 로컬 분석 맥락의 부연이며 규칙 충돌 시 PRIMITIVE_GATE가 이긴다.

- `/proc/<pid>/maps`, gdb, core, 고정 ASLR로 얻은 관측은 그 의존성을 명시한다. 일반 실행 또는 Docker/loopback에서도 재현되는지 구분한다.
- Dockerfile이 있으면 이미지의 libc·loader와 loopback 조건을 우선 증거로 사용한다. mismatch는 추측이 아니라 hash, build-id, leak 등 로컬 증거가 있어야 한다.

## context 규율

- raw dump보다 bounded query를 우선한다. `decomp`와 `gdbq`도 필요한 함수/측정에만 사용한다.
- 주소·offset·gadget·layout은 evidence-backed typed observation (`kind:"pwn.offset"`)으로 기록한다. 문서의 예시 수치를 복사해 사용하지 않는다.
- 상태 읽기: `rat state compact --budget-tokens N`이 기본이다. `state show`는 DEEP에서 전체 materialized 뷰가 실제로 필요할 때만 쓰며 STATE 원본(`STATE.v2.jsonl`)을 통째로 붙여넣지 않는다.
- 같은 deterministic artifact를 반복 주입하지 않는다. cache/index가 장기 truth이고 모델 context는 현재 branch의 working set이다.
- 반증된 branch의 raw 출력은 context에서 제거하고 가설·실패·재현 조건은 즉시 append한다.

## 로컬 도구

| 목적 | 명령 |
|---|---|
| 현재 evidence snapshot | `rat state compact --budget-tokens N` |
| route 재평가(필요할 때만) | `rat route <bin>` |
| bounded 구조 조회 | `rat query func|oracle|pwn|pattern|slice ...` |
| 함수 단위 디컴파일 | `decomp <bin> <func>` |
| 배치 관찰 | `gdbq <bin> "b *main" "run"` |
| 로컬 스캐폴드(최초 ingest에만) | `newchal <name> <bin> [libc]` |
| 로컬 검증 | `rat-verify ...` / `./solve_local.py` / `pwnkit.run_batch(...)` |
| 상태 기록 | `state hypothesis`, typed `state event append`, typed `state primitive`, `state route`, `state failclass` |

## 협업

- 한 번에 활성 문제는 하나다.
- 팬아웃은 독립된 경쟁 branch가 실제로 2~3개 존재하고 한 실험으로 합치기 어려울 때만 최대 3개까지 사용한다.
- 각 subagent는 서로 다른 branch 또는 큰 bounded read만 맡고 main agent에는 결론·증거 digest·falsifier만 반환한다.
- 동일 함수/동일 hypothesis를 여러 agent가 반복 분석하지 않는다.
- primitive 검증과 PoC 조립은 순차적으로 수렴한다.
- deterministic verifier가 명확한 경우 skeptic은 기본 OFF다. 환경 민감·증거 충돌·해석 불일치가 남을 때만 사용한다.
- 에이전트는 외부 상호작용을 수행하거나 다른 에이전트에게 맡기지 않는다. 범위 밖 요구는 기록하고 멈춘다.

## 산출물

- `.rat/events/STATE.v2.jsonl`: typed 사실, 가설, 측정값, 실패 경로, 다음 검증 단계 (`STATE.jsonl`은 legacy import/inspection 전용)
- `solve_local.py`: 네트워크 없이 실행되는 재현 스크립트 또는 최소 입력
- 기본 `HANDOFF.md`: primitive 입력·환경 digest, marker 증거, 제약 및 미검증 조건
- 증거 digest가 연결된 operator attestation이 있는 경우에만 `WRITEUP.md` 또는 `SUBMISSION.md`
- 검토 후 일반화한 교훈: `knowledge/learned/`의 candidate/validated/reused 문서
