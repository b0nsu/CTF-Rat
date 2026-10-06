# Primitive Gate — SELF 확인 전 체이닝 금지

> **DEEP 전용 문서.** CLAUDE.md FAST hot-path에서는 로드하지 않는다. DEEP 승격 조건 충족 시 또는 명시 요청 시에만 읽는다.

목적: “될 것 같은 가설”을 “검증된 primitive”처럼 쓰는 실수를 막는다. 로컬 PoC를 조립하기 전에, 최소 입력으로 control primitive가 실제 바이너리에서 증명되어야 한다.

## 상태 타입

- `state hypothesis <text>`: 아직 검증 전인 풀이 가설. 체이닝 근거로 사용 금지.
- `state primitive candidate <rat.primitive/v1 doc.json>`: 후보 등록(typed v2, `status:"candidate"`). PASS 근거로는 사용 불가.
- **PASS 기록(typed STATE v2 전용, 필수)**: `state primitive <name> pass <evidence>` 형태의 legacy 명령은 `bin/state`가 거부한다. PASS는 아래 3단계로 typed v2 스트림에 기록해야 한다.
  1. SELF로 직접 확인한 관찰 3개 이상을 `rat.observation/v1` 문서로 각각 기록: `state event append obs_N.json` (각 문서는 `quality.level:"direct"`, `validity.state:"active"`).
  2. `rat.primitive/v1` 문서를 작성: `status:"pass"`, `self_evidence:[관찰 3개 이상의 observation_id]`, 나머지 필수 필드(`primitive_id`,`name`,`class`,`input_digest`,`environment_digest`,`constraints`,`side_effects`,`remote_equivalent`,`producer`,`revision`). **`input_digest`/`environment_digest`는 자유값이 아니다**: SELF observation의 direct 증거 봉투가 실제로 측정한 subject·environment 해시와 정확히 일치해야 한다(도구가 봉투에 stamp한 `subject_digest`/`environment_digest`). 불일치 시 `revise_primitive`가 "PASS SELF evidence must measure the primitive input_digest/environment_digest"로 거부한다 — 바이너리 A의 증거로 바이너리 B PASS를 만들 수 없다.
  3. `state primitive pass primitive.json` 로 typed v2 스트림에 append — `bin/state`/`ratlib.state_v2.revise_primitive`가 "3개의 distinct active+direct SELF observation + 3개의 distinct evidence artifact + input/environment binding" invariant를 실제로 검증한다. 또한 아래 canonical primitive class는 **class별 proof slot coverage**까지 통과해야 한다.
- `state primitive fail <rat.primitive/v1 doc.json>` / `state primitive block <rat.primitive/v1 doc.json>`: primitive 실패/보류. **legacy 텍스트 로그는 `bin/state`가 거부하므로 fail/blocked도 typed v2 문서가 필수**다(각각 `status:"fail"` / `status:"blocked"`). 명령어는 `block`, 문서 status는 `blocked`로 서로 다름에 주의. 같은 경로로 체이닝 금지.
- `state no <text> -- <reason>`: 재시도 금지 dead-end.

## Primitive proof contract

generic gate(`>=3` distinct active+direct SELF)는 모든 PASS의 바닥 조건이다. 그러나 canonical class는 같은 사실을 세 번 측정한 것만으로 PASS할 수 없다. 각 class의 proof slot은 kind와 hash-covered verifier 결과의 의미 검증을 함께 통과해야 한다.

| primitive class | contract | required proof slots |
|---|---|---|
| `control-flow` | `control-flow/v2` | control state: `pwn.reg*` 또는 `pwn.control-flow.state*` · attacker marker: `pwn.marker*` 또는 `pwn.memory-control*` · control target: 검증된 입력 변경 → 제어 대상 → 제어 이전 관계 (현재 producer 미지원) |
| `solution-reconstruction` | `solution-reconstruction/v2` | recovered input: `rev.solution.input*` 또는 `rev.symsolve.input*` · success oracle: `rev.solution.oracle*` 또는 `rev.oracle*` · concrete replay: `rev.solution.replay*` 또는 `rev.symsolve.concrete-verify*` |

신규 PASS는 계약 필드가 없으면 현재 버전을 채우고 null·빈 문자열·잘못된 버전은 거부한다.
필드가 실제로 없는 과거 history와 v1 계약은 읽을 수 있지만 현재 consume에는 재검증이 필요하다.
과거 이벤트를 복사해 신규 revise할 때도 현재 계약을 검사한다. 이 호환은 작성 시점 인증이 아니다.

REV oracle/replay는 GDB transcript와 분리한 inferior stdout/stderr artifact에서만 성공 문자열을 찾는다.
artifact digest·size·완전성·invocation/subject binding을 immutable envelope와 대조하며, 정상 종료는
debugger transcript에서 별도로 확인한다. sentinel은 실행 완료 보조 정보다.

PASS 시 runtime은 canonical class의 `extensions.proof_contract`를 해당 version으로 고정하고, self_evidence에 각 slot을 만족하는 observation이 실제로 있는지 검사한다. 하나의 observation이 여러 slot을 대신하지 못하도록 slot 수만큼 distinct observation coverage도 요구한다.

기존 자유 문자열 class는 backward compatibility 때문에 generic gate만 적용한다. 신규 PWN control-flow 및 REV solution-reconstruction primitive는 위 canonical class를 사용한다. canonical class를 피하기 위해 임의 class 문자열로 바꾸는 것은 verification 우회로 간주한다.

`rev.symsolve.concrete-verify`라는 kind 이름 자체는 direct를 의미하지 않는다. 다른 observation과 동일하게 evidence envelope에서 runtime이 `quality.level=direct`를 재계산해야 해당 proof slot에 사용 가능하다.

## Primitive PASS 조건

primitive PASS는 “가능성”이 아니라 “제어성”까지 증명해야 한다.

필수 증거:

1. 최소 입력으로 재현된다.
2. gdb 전용이 아니라 일반 실행 core 또는 loopback/Docker 실행에서 확인했다.
3. EIP/RIP, ESP/RSP/RBP, 주요 register를 기록했다.
4. control target이 예상 주소와 일치한다.
5. target memory가 단순 readable이 아니라 attacker-controlled임을 marker로 증명했다.
6. `strcpy`, `strlen`, `gets`, `read`, newline 등 terminator/length 부작용을 확인했다.
7. ASLR, argv/env 길이, libc/kernel/vDSO 차이 같은 layout 의존성을 기록했다.

Heap/tcache primitive 는 추가로 아래를 증명해야 한다.

8. 같은 malloc/free 순서에서 tcache bin의 `count`, head, next 반환 순서를 확인했다.
9. safe-linking 대상이면 `encoded_fd == target ^ (chunk_addr >> 12)` 를 실측 주소로 계산했다.
10. 실패 원인을 libc mismatch 로 올리기 전에 Docker/loopback 또는 leak/build-id/hash 증거를 확보했다.

예 — canonical proof observation은 가능한 한 수동 JSON 작성 대신 `rat-adapt --proof` 경로로 만든다.

`rat-adapt --proof`는 신뢰된 verifier(`gdbq`/`symsolve`)의 direct envelope을 만든 뒤, **immutable capture를 proof mode별 parser로 다시 검증한 경우에만** 지원하는 observation을 STATE에 기록한다. PWN proof mode에서는 임의 GDB command를 받지 않고 adapter가 bounded command를 직접 생성한다. 같은 envelope/kind는 active이며 현재 의미 검증과 값이 일치할 때만 재사용한다. invalidated/stale capture는 거부하며 `--fresh`로 실제 새 invocation을 실행해야 한다.

### PWN 관찰의 지원 범위

`pwn-control-state`는 register snapshot, `pwn-memory-control`은 marker 일치만 기록한다.
`pwn-control-target`은 일반 word 일치만 확인하므로 `pwn.memory-word`로 기록하고
`control_relation_proven:false`를 반환한다. 이 세 관찰을 조합해도 `control-flow/v2` PASS는 거부한다.
현재 verifier는 입력이 제어 대상을 변경하고 그 대상이 제어 이전에 사용되는 동일 scenario 관계를
증명하지 못한다. `pwn.offset`이나 kind prefix도 control-target 슬롯을 대신할 수 없다.

모든 GDB proof run은 inferior stdout/stderr와 debugger 응답을 별도 immutable artifact로 저장한다.
PWN parser는 adapter가 삽입한 단일 measurement 구간만 읽고, memory 응답에 출력된 실제 주소가
같은 구간의 계산 주소와 일치하는지 확인한다. 분리 capture의 invocation/subject/digest/완전성 중
하나라도 맞지 않으면 observation을 만들지 않는다. 이 계약 이전의 PWN envelope는 history에서는
읽을 수 있지만 새 observation으로 재사용할 수 없으며 `--fresh` 재측정이 필요하다.

### REV solution-reconstruction/v2

solver 자체를 반복 세 번 돌릴 필요는 없다. recovered input은 `symsolve` direct run에서 한 번 얻고, 나머지 두 slot은 그 concrete input을 `gdbq`로 독립 재실행해 채운다.
solution parser는 producer가 출력하는 `stdin`, `argv1`, `file` 라벨을 각각 보존하며, 과거
`file:<path>` 라벨도 읽는다.

```sh
# 1) symbolic reconstruction. symsolve stdout의 concrete hex를 parser가 추출해 기록.
bin/rat-adapt --root .rat --input ./checker --direct-subject ./checker \
  --proof rev-solution-input \
  symsolve ./checker --find-str Correct --stdin 16 --printable

# 위 observation의 solutions 값을 concrete.bin으로 materialize한 뒤:
# 2) success oracle
bin/rat-adapt --root .rat --input ./checker --direct-subject ./checker \
  --proof rev-success-oracle --proof-input concrete.bin --proof-expect Correct \
  gdbq

# 3) 별도 concrete replay
bin/rat-adapt --root .rat --input ./checker --direct-subject ./checker \
  --proof rev-concrete-replay --proof-input concrete.bin --proof-expect Correct \
  gdbq
```

proof mode가 없는 기존 `rat-adapt ... gdbq --batch ...` 경로와 수동 `state event append`는 compatibility/특수 분석용으로 남아 있다. 그러나 canonical proof contract를 채우는 기본 경로는 위 semantic producer다. `quality.level`은 여전히 호출자가 정하지 않으며, STATE가 envelope bytes에서 direct/derived/heuristic을 재계산한다.

`state schema rat.primitive/v1` / `state schema rat.observation/v1`로 필수 필드 스키마를 직접 확인할 수 있다.

## 금지 규칙

아래 중 하나라도 해당하면 로컬 PoC 조립 금지:

- `state hypothesis`만 있고 typed v2 `state primitive pass <doc.json>` 기록이 없다.
- pivot 주소가 readable일 뿐 attacker-controlled marker가 없다.
- gdb에서는 되지만 일반 실행 core에서 깨진다.
- terminator/NUL/newline이 다음 byte 또는 chain을 훼손하는지 확인하지 않았다.
- tcache poisoning/dup 경로에서 bin count/head/fd를 확인하지 않고 실행 환경 차이로 추정했다.
- Dockerfile이 제공됐는데 이미지 안의 libc/loader 해시 또는 loopback 서비스 검증 없이 libc mismatch를 주장했다.

이 문서는 로컬 실행의 증거만 다룬다. 외부 시스템에 대한 실행·반복·성공 판정은 primitive 검증 절차에 포함하지 않는다.

## 재현성 규칙

- 로컬 PoC는 deterministic하게 재현되어야 한다.
- 반복 실행으로 ASLR, canary, heap layout, timing race, partial overwrite 확률을 맞추는 경로는 풀이 전략으로 승격하지 않는다.
- 측정용 반복은 가설 검증에만 사용하며, 불안정한 경로는 `state no`로 기록하고 분석으로 돌아간다.

## SELF 체크리스트

로컬 PoC 작성 전에 확인:

```text
[ ] 이건 hypothesis인가, primitive PASS인가?
[ ] 최소 입력으로 EIP/ESP/RSP 이동을 확인했나?
[ ] 일반 실행 core 또는 loopback/Docker 실행인가?
[ ] target memory에 attacker marker가 있나?
[ ] terminator/NUL/strlen/strcpy 부작용을 확인했나?
[ ] ASLR/env/argv/layout 의존성을 기록했나?
[ ] 반복 실행으로 확률 조건을 맞추는 경로는 아닌가?
[ ] heap이면 tcache count/head/fd와 safe-linking encoding을 같은 sequence에서 확인했나?
[ ] libc mismatch 가설이면 Docker image hash/loopback, leak, build-id 중 하나로 증명했나?
[ ] 실패 경로는 state no 또는 primitive fail로 기록했나?
```

## Engine provenance / trust boundary (completion gate)

`symsolve --record-state-dir <challenge-dir>`는 concrete-verify 성공 시 heuristic STATE observation과
연결된 rev-symbolic primitive revision을 자동 기록한다. completion gate는 primitive의
`producer.engine`이나 `solve_origin` 태그만으로 판단하지 않는다. `solution-reconstruction` 등
허용된 복원 class, 또는 직접 측정한 PWN SELF observation이 없는 rev route-assessment가 있으면 태그 없이도 연결된 활성
`rev.symsolve.concrete-verify` observation의 engine provenance를 확인하고, 근거가 없으면 기본
deny한다. 그 observation의 `engine_identity.harness_sha256`은 trusted verifier manifest와
대조하고 합성 `engine_build_digest`와의 일치를 확인한다. 이전 형식처럼 `engine_identity`가
없는 기록은 새 concrete-verify 또는 수동 attestation이 필요하다. 뒤에 추가된 PWN route note만으로 앞선 rev 후보를 지우지 않으며, active+direct
`pwn.*` SELF observation은 잠정적 rev route보다 우선한다. Router v2의 rev lead와 PWN lead가
한 note에 함께 있으면 그 note만으로 rev 분류하지 않는다.
rev route note가 없거나 혼합 lead뿐이고 primitive class가 allowlist 밖이면 이 분류로는 잡히지 않는다.
PWN SELF observation의 kind가 `pwn.*`가 아닌 정당한 PWN solve는 잠정 rev route 때문에
오탐될 수 있으므로 수동 attestation 또는 명시적 route 근거 정리가 필요하다.
수동 solve는 유효한 `rat.writeup-attestation/v1`로 통과할 수 있다.
환경변수로 엔진 게이트를 완화하는 경로는 없다.

이 trust boundary는 로컬 랩 규약이며 STATE JSONL과 observation에는 작성자 서명이 없다. 따라서
실행자는 평문 append로 sanctioned observation과 route note를 위조할 수 있고, 게이트는 이를 구별하지 못한다.
`operator_attestation`도 서명된 운영자 증명이 아니다. 코드는 스키마·시간·현재 solve에서 사용 가능한
evidence 참조만 검사하므로, 해당 JSONL을 쓸 수 있는 실행자는 attestation도 위조할 수 있다.
완전한 작성자 인증에는 서명 또는 out-of-band 운영자 신호가 필요하다.
