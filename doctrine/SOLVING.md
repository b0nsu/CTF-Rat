# 로컬 CTF artifact 분석·재현 규약

> **DEEP 전용 문서.** CLAUDE.md FAST hot-path에서는 로드하지 않는다. DEEP 승격 조건(모호한 결과·env-민감·
> 같은 실패 반복·evidence 충돌·Progress Novelty Governor stuck) 충족 시, 또는 사용자가 명시적으로 요청할 때만 읽는다.

## 범위

- 제공된 바이너리·소스·libc·Docker·loopback 환경만 분석하고 실행한다.
- 제공 artifact·challenge 디렉터리·로컬 Docker/loopback에서 challenge가 의도적으로 노출하는 flag는 end-to-end 로컬 재현 증거로 읽을 수 있다. 이는 외부 결과 획득이나 제출 완료를 뜻하지 않는다.
- 외부 호스트·포트·계정·대회 인프라와의 접속, 스캔, 결과 획득 및 제출은 이 규약의 범위 밖이다. 사용자 홈·SSH 키·토큰·환경변수 등 실제 자격증명 탐색도 금지한다.
- 요청이 거부되었거나 범위가 불명확하면 표현 변경, 작업 분할, 하위 에이전트로 재시도하지 않는다. 로컬 분석 결과만 기록한다.

## 미션

userland x86-64 Linux pwn/rev artifact를 빠르게 분류하고, 취약점 또는 검증 로직을 로컬에서 재현 가능한 증거와 최소 PoC로 정리한다. 완료 기준은 외부 결과가 아니라 **로컬에서 재현되는 분석 결론**이다.

## 고정 루프

0. `ctfguard begin <name>`으로 로컬 active lock을 만들고 `ctfguard check`가 GREEN인지 확인한다.
1. 제공된 artifact에 `newchal <name> <bin> [libc]`를 실행하고 `recon`(pwn) 또는 `revq`(rev)로 triage한다.
2. `decomp <bin> <func>`로 관련 함수 하나씩 확인해 vuln class 또는 검증 경로를 확정한다.
3. `knowledge/GROUNDING_INDEX.md`에서 해당하는 **로컬 분석 자료 하나**만 선택한다. 큰 읽기는 요약 작업으로 위임한다.
4. 후보는 `state hypothesis ...`로 기록한다. `doctrine/PRIMITIVE_GATE.md`의 SELF 확인을 통과하기 전에는 PoC를 조립하지 않는다.
5. primitive PASS 뒤에만 `solve_local.py` 또는 최소 PoC를 로컬 process/Docker에서 검증한다.
6. skeptic 검토로 marker 오인, libc/loader mismatch, ASLR·입력 길이·환경 차이를 반증한다.
7. 검증된 로컬 재현 절차와 한계를 typed STATE v2 stream 및 선택적 writeup에 남긴다. 로컬 flag를 읽은 경우에는 대상·실행 조건·환경 digest를 함께 기록한다.

## 재현성 규칙

> 재현성·확률 경로 금지의 **단일 출처는 [doctrine/PRIMITIVE_GATE.md](PRIMITIVE_GATE.md)의 "재현성 규칙" 절**이다. 아래는 로컬 분석 맥락의 부연이며 규칙 충돌 시 PRIMITIVE_GATE가 이긴다.

- `/proc/<pid>/maps`, gdb, core, 고정 ASLR로 얻은 관측은 그 의존성을 명시한다. 일반 실행 또는 Docker/loopback에서도 재현되는지 구분한다.
- Dockerfile이 있으면 이미지의 libc·loader와 loopback 조건을 우선 증거로 사용한다. mismatch는 추측이 아니라 hash, build-id, leak 등 로컬 증거가 있어야 한다.

## context 규율

- `decomp`와 `gdbq`를 우선 사용한다. 함수 목록·문자열·xref의 대량 읽기는 요약만 회수한다.
- 주소·offset·gadget·layout은 evidence-backed typed observation (`kind:"pwn.offset"`)으로 기록한다. 문서의 예시 수치를 복사해 사용하지 않는다.
- 상태 읽기: FAST hot-path에서는 `state compact --budget-tokens N`(토큰 bounded 뷰)이 기본이다. `state show`는 DEEP에서 전체 materialized 뷰가 필요할 때 쓰는 상위 명령이며 STATE 원본(`STATE.v2.jsonl`)을 통째로 붙여넣지 않는다. 가설·실패·재현 조건은 즉시 append한다.

## 로컬 도구

| 목적 | 명령 |
|---|---|
| 정찰·triage | `recon <bin> [libc]` / `revq <bin>` |
| 디컴파일 | `decomp <bin> [func]` |
| 배치 관찰 | `gdbq <bin> "b *main" "run"` |
| 로컬 스캐폴드 | `newchal <name> <bin> [libc]` |
| 로컬 검증 | `./solve_local.py` 또는 `pwnkit.run_batch(...)` |
| 상태 기록 | `state hypothesis`, typed `state event append`, typed `state primitive`, `state route`(ruled-out 경로 기록 = 재시도 금지 dead-end), `state alert` |

## 협업

- 한 번에 활성 문제는 하나다. 팬아웃은 큰 정적 읽기 또는 vuln class가 불확실한 경우에만 최대 3개까지 사용한다.
- primitive 검증과 PoC 조립은 순차적으로 수렴한다. skeptic은 완료 선언 전 로컬 재현을 반증한다.
- 에이전트는 외부 상호작용을 수행하거나 다른 에이전트에게 맡기지 않는다. 범위 밖 요구는 기록하고 멈춘다.

## 산출물

- `.rat/events/STATE.v2.jsonl`: typed 사실, 가설, 측정값, 실패 경로, 다음 검증 단계 (`STATE.jsonl`은 legacy import/inspection 전용)
- `solve_local.py`: 네트워크 없이 실행되는 재현 스크립트 또는 최소 입력
- 기본 `HANDOFF.md`: primitive 입력·환경 digest, marker 증거, 제약 및 미검증 조건
- 증거 digest가 연결된 operator attestation이 있는 경우에만 `WRITEUP.md` 또는 `SUBMISSION.md`
- 검토 후 일반화한 교훈: `knowledge/learned/`의 candidate/validated/reused 문서
