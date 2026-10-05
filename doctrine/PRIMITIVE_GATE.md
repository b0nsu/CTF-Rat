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

generic gate(`>=3` distinct active+direct SELF)는 모든 PASS의 바닥 조건이다. 그러나 canonical class는 같은 사실을 세 번 측정한 것만으로 PASS할 수 없다. 각 class가 요구하는 서로 다른 의미의 proof slot을 observation `kind`로 덮어야 한다.

| primitive class | contract | required proof slots |
|---|---|---|
| `control-flow` | `control-flow/v1` | control state: `pwn.reg*` 또는 `pwn.control-flow.state*` · attacker marker: `pwn.marker*` 또는 `pwn.memory-control*` · control target: `pwn.control-target*` 또는 `pwn.offset` |
| `solution-reconstruction` | `solution-reconstruction/v1` | recovered input: `rev.solution.input*` 또는 `rev.symsolve.input*` · success oracle: `rev.solution.oracle*` 또는 `rev.oracle*` · concrete replay: `rev.solution.replay*` 또는 `rev.symsolve.concrete-verify*` |

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

`rat-adapt --proof`는 신뢰된 verifier(`gdbq`/`symsolve`)의 direct envelope을 만든 뒤, **실제 stdout을 proof mode별 parser로 다시 검증한 경우에만** canonical observation을 STATE에 기록한다. PWN proof mode에서는 임의 GDB command를 받지 않고 adapter가 bounded command를 직접 생성한다. 같은 envelope/kind를 다시 기록하려 하면 기존 observation을 재사용한다.

### PWN control-flow/v1

아래 예에서 `payload.bin`은 이미 준비한 최소 재현 입력이고 `proof_stop`은 검사할 안정적인 breakpoint다. `--proof-address`는 `$rsp`, `$rdi`, `0x...` 및 단일 +/- offset 형태만 허용하며 command injection 문자열은 거부한다.

```sh
state hypothesis "local control-flow candidate"

# 1) control-state: breakpoint hit 뒤 RIP/RSP(/RBP)를 gdbq가 직접 측정.
bin/rat-adapt --root .rat --input ./chal --direct-subject ./chal \
  --proof pwn-control-state --proof-input payload.bin --proof-break proof_stop \
  gdbq

# 2) attacker-marker: 지정 주소의 실제 bytes가 marker와 정확히 일치해야 기록.
bin/rat-adapt --root .rat --input ./chal --direct-subject ./chal \
  --proof pwn-memory-control --proof-input payload.bin --proof-break proof_stop \
  --proof-address '$rsp+8' --proof-marker 4141414141414141 \
  gdbq

# 3) control-target: 지정 word의 실측 값이 예상 target과 정확히 일치해야 기록.
bin/rat-adapt --root .rat --input ./chal --direct-subject ./chal \
  --proof pwn-control-target --proof-input payload.bin --proof-break proof_stop \
  --proof-address '$rsp' --proof-target 0x401234 \
  gdbq

# 위 세 실행은 각각 다른 direct envelope과 canonical observation을 만든다.
# state show에서 observation_id를 확인해 primitive.json.self_evidence에 넣는다.
state primitive --example > primitive.json
# class:"control-flow", status:"pass", self_evidence:[세 observation_id],
# input/environment digest를 실제 측정값에 맞춘 뒤:
state primitive pass primitive.json
```

각 proof mode는 다음 kind만 생성한다.

| proof mode | canonical observation kind | parser가 확인하는 것 |
|---|---|---|
| `pwn-control-state` | `pwn.reg` | breakpoint 실제 hit + RIP/RSP 존재 |
| `pwn-memory-control` | `pwn.memory-control` | breakpoint hit + 지정 주소 bytes == marker |
| `pwn-control-target` | `pwn.control-target` | breakpoint hit + 지정 word == target |
| `rev-solution-input` | `rev.solution.input` | symsolve가 concrete solution hex를 실제 출력 |
| `rev-success-oracle` | `rev.solution.oracle` | concrete input 실행이 정상 종료 + 기대 문자열 출력 |
| `rev-concrete-replay` | `rev.solution.replay` | 별도 concrete replay 정상 종료 + 기대 문자열 + replay sentinel |

### REV solution-reconstruction/v1

solver 자체를 반복 세 번 돌릴 필요는 없다. recovered input은 `symsolve` direct run에서 한 번 얻고, 나머지 두 slot은 그 concrete input을 `gdbq`로 독립 재실행해 채운다.

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
