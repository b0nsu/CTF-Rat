# Primitive Gate — SELF 확인 전 체이닝 금지

> **DEEP 전용 문서.** CLAUDE.md FAST hot-path에서는 로드하지 않는다. DEEP 승격 조건 충족 시 또는 명시 요청 시에만 읽는다.

목적: “될 것 같은 가설”을 “검증된 primitive”처럼 쓰는 실수를 막는다. 로컬 PoC를 조립하기 전에, 최소 입력으로 control primitive가 실제 바이너리에서 증명되어야 한다.

## 상태 타입

- `state hypothesis <text>`: 아직 검증 전인 풀이 가설. 체이닝 근거로 사용 금지.
- `state primitive <name> candidate <evidence>`: 후보 등록(legacy 텍스트 로그). PASS 근거로는 사용 불가.
- **PASS 기록(typed STATE v2 전용, 필수)**: `state primitive <name> pass <evidence>` 형태의 legacy 명령은 `bin/state`가 거부한다. PASS는 아래 3단계로 typed v2 스트림에 기록해야 한다.
  1. SELF로 직접 확인한 관찰 3개 이상을 `rat.observation/v1` 문서로 각각 기록: `state event append obs_N.json` (각 문서는 `quality.level:"direct"`, `validity.state:"active"`).
  2. `rat.primitive/v1` 문서를 작성: `status:"pass"`, `self_evidence:[관찰 3개 이상의 observation_id]`, 나머지 필수 필드(`primitive_id`,`name`,`class`,`input_digest`,`environment_digest`,`constraints`,`side_effects`,`remote_equivalent`,`producer`,`revision`).
  3. `state primitive pass primitive.json` 로 typed v2 스트림에 append — `bin/state`/`ratlib.state_v2.revise_primitive`가 "3개의 active+direct SELF observation" invariant를 실제로 검증한다.
- `state primitive <name> fail|blocked <evidence>`: primitive 실패/보류(legacy 텍스트 로그로 허용). 같은 경로로 체이닝 금지.
- `state no <text> -- <reason>`: 재시도 금지 dead-end.

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

예:

```sh
state hypothesis "saved EBP low-byte overwrite may pivot main epilogue into attacker-controlled stack data"

# 최소 입력 실행 후 core/gdb에서 SELF로 직접 확인한 관찰을 3개 이상 기록:
#   obs_esp.json:   {"schema":"rat.observation/v1", ..., "value":"ESP=0xfffc00bf",
#                    "quality":{"level":"direct"}, "validity":{"state":"active"}, ...}
#   obs_marker.json:{"schema":"rat.observation/v1", ..., "value":"[ESP]=0x41424344 attacker marker", ...}
#   obs_ret.json:   {"schema":"rat.observation/v1", ..., "value":"next ret target=0x80000000", ...}
state event append obs_esp.json
state event append obs_marker.json
state event append obs_ret.json

# primitive.json: {"schema":"rat.primitive/v1", "status":"pass",
#                   "self_evidence":["<obs_esp id>","<obs_marker id>","<obs_ret id>"], ...}
state primitive pass primitive.json
```

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
