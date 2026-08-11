# Primitive Gate — SELF 확인 전 체이닝 금지

목적: “될 것 같은 가설”을 “검증된 primitive”처럼 쓰는 실수를 막는다. 최소 입력으로 control primitive가 실제 바이너리에서 증명되면 자동 작업은 종료하고 운영자에게 인계한다.

## 상태 타입

- `state hypothesis <text>`: 아직 검증 전인 풀이 가설. 체이닝 근거로 사용 금지.
- `state primitive <name> pass <evidence>`: 최소 입력으로 검증된 primitive. 자동 범위의 종료·운영자 인계 근거.
- `state primitive <name> fail|blocked <evidence>`: primitive 실패/보류. 같은 경로로 체이닝 금지.
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

# 최소 입력 실행 후 core/gdb에서:
#   ESP=0xfffc00bf
#   [ESP]=0x41424344 (입력의 marker)
#   next ret target=0x80000000
state primitive stack_pivot pass "core: ESP=0xfffc00bf, [ESP]=0x41424344 attacker marker, next ret=0x80000000"
```

## 자동화 종료 규칙

primitive PASS 뒤에는 Codex가 payload를 조립하거나 chain을 실행하지 않는다. 인계물에는 입력·환경 digest, marker 증거, 알려진 제약 및 남은 체이닝 조건을 포함한다.

## 금지 규칙

아래 중 하나라도 해당하면 primitive PASS 승격 금지:

- `state hypothesis`만 있고 `state primitive ... pass`가 없다.
- pivot 주소가 readable일 뿐 attacker-controlled marker가 없다.
- gdb에서는 되지만 일반 실행 core에서 깨진다.
- terminator/NUL/newline이 다음 byte 또는 chain을 훼손하는지 확인하지 않았다.
- tcache poisoning/dup 경로에서 bin count/head/fd를 확인하지 않고 실행 환경 차이로 추정했다.
- Dockerfile이 제공됐는데 이미지 안의 libc/loader 해시 또는 loopback 서비스 검증 없이 libc mismatch를 주장했다.

이 문서는 로컬 실행의 증거만 다룬다. 외부 시스템에 대한 실행·반복·성공 판정은 primitive 검증 절차에 포함하지 않는다.

## 재현성 규칙

- primitive 증거는 deterministic하게 재현되어야 한다.
- 반복 실행으로 ASLR, canary, heap layout, timing race, partial overwrite 확률을 맞추는 경로는 풀이 전략으로 승격하지 않는다.
- 측정용 반복은 가설 검증에만 사용하며, 불안정한 경로는 `state no`로 기록하고 분석으로 돌아간다.

## SELF 체크리스트

primitive PASS 기록 전에 확인:

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
[ ] PASS 뒤에 자동화를 종료하고 운영자 인계 조건을 기록했나?
```
