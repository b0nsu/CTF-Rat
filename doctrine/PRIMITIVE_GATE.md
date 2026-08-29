# Primitive Gate — SELF 확인 전 체이닝 금지

> **DEEP 전용 문서.** CLAUDE.md FAST hot-path에서는 로드하지 않는다. DEEP 승격 조건 충족 시 또는 명시 요청 시에만 읽는다.

목적: “될 것 같은 가설”을 “검증된 primitive”처럼 쓰는 실수를 막는다. 로컬 PoC를 조립하기 전에, 최소 입력으로 control primitive가 실제 바이너리에서 증명되어야 한다.

## 상태 타입

- `state hypothesis <text>`: 아직 검증 전인 풀이 가설. 체이닝 근거로 사용 금지.
- `state primitive candidate <rat.primitive/v1 doc.json>`: 후보 등록(typed v2, `status:"candidate"`). PASS 근거로는 사용 불가.
- **PASS 기록(typed STATE v2 전용, 필수)**: `state primitive <name> pass <evidence>` 형태의 legacy 명령은 `bin/state`가 거부한다. PASS는 아래 3단계로 typed v2 스트림에 기록해야 한다.
  1. SELF로 직접 확인한 관찰 3개 이상을 `rat.observation/v1` 문서로 각각 기록: `state event append obs_N.json` (각 문서는 `quality.level:"direct"`, `validity.state:"active"`).
  2. `rat.primitive/v1` 문서를 작성: `status:"pass"`, `self_evidence:[관찰 3개 이상의 observation_id]`, 나머지 필수 필드(`primitive_id`,`name`,`class`,`input_digest`,`environment_digest`,`constraints`,`side_effects`,`remote_equivalent`,`producer`,`revision`). **`input_digest`/`environment_digest`는 자유값이 아니다**: SELF observation의 direct 증거 봉투가 실제로 측정한 subject·environment 해시와 정확히 일치해야 한다(도구가 봉투에 stamp한 `subject_digest`/`environment_digest`). 불일치 시 `revise_primitive`가 "PASS SELF evidence must measure the primitive input_digest/environment_digest"로 거부한다 — 바이너리 A의 증거로 바이너리 B PASS를 만들 수 없다.
  3. `state primitive pass primitive.json` 로 typed v2 스트림에 append — `bin/state`/`ratlib.state_v2.revise_primitive`가 "3개의 active+direct SELF observation" invariant를 실제로 검증한다.
- `state primitive fail <rat.primitive/v1 doc.json>` / `state primitive block <rat.primitive/v1 doc.json>`: primitive 실패/보류. **legacy 텍스트 로그는 `bin/state`가 거부하므로 fail/blocked도 typed v2 문서가 필수**다(각각 `status:"fail"` / `status:"blocked"`). 명령어는 `block`, 문서 status는 `blocked`로 서로 다름에 주의. 같은 경로로 체이닝 금지.
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

예 (스캐폴드는 `state event --example` / `state primitive --example`로 그대로 뽑아 값만 채운다):

**중요**: `evidence`는 사람이 쓴 설명 object가 아니라 **content-addressed artifact digest 문자열 배열**이다
(`["sha256:..."]`). `quality.level`도 호출자가 주장하는 값이 아니라, 인용한 evidence artifact의
해시된 바이트에서 런타임이 재계산한다(`state_v2._evidence_quality`) — 아래처럼 `quality`를
아무 값이나 채워 보내도 실제 값으로 덮어써진다. "direct"를 얻으려면 evidence가 신뢰된 verifier
(`gdbq`/`symsolve`)의 `rat.tool-result/v1` 성공 envelope를 가리켜야 하고, 그 envelope는 실제로
`subject_path`(대상 바이너리)를 측정한 것이어야 한다. `rat-adapt`가 이 envelope를 만드는 유일한
공개 CLI 경로다:

```sh
state hypothesis "saved EBP low-byte overwrite may pivot main epilogue into attacker-controlled stack data"

# 1) 최소 입력으로 신뢰된 verifier(gdbq)를 실제 측정 모드로 실행 -- --direct-subject가
#    이 실행을 SELF-measurement로 표시하고, 결과 envelope에 subject_digest/environment_digest를
#    바인딩한다. 세 개의 서로 다른 측정을 세 번 실행해 서로 다른 envelope 3개를 얻는다.
r1=$(bin/rat-adapt --root .rat --input ./chal --direct-subject ./chal gdbq --batch regs.gdb | \
     python3 -c 'import json,sys; print(json.load(sys.stdin)["extensions"]["envelope_digest"])')
r2=$(bin/rat-adapt --root .rat --input ./chal --direct-subject ./chal gdbq --batch marker.gdb | \
     python3 -c 'import json,sys; print(json.load(sys.stdin)["extensions"]["envelope_digest"])')
r3=$(bin/rat-adapt --root .rat --input ./chal --direct-subject ./chal gdbq --batch ret.gdb | \
     python3 -c 'import json,sys; print(json.load(sys.stdin)["extensions"]["envelope_digest"])')

# 2) 각 envelope digest를 evidence로 인용하는 관찰을 기록. quality/validity는 필수 필드지만
#    quality.level 값 자체는 런타임이 evidence로부터 재계산하므로 여기 값은 힌트일 뿐이다.
cat > obs_rsp.json <<JSON
{"schema":"rat.observation/v1","observation_id":"obs_rsp","run_id":"run_1",
 "created_at":"2026-01-01T00:00:00Z","producer":{"tool":"gdbq","version":"1"},
 "subject":{"binary":"./chal"},"kind":"pwn.reg","value":"RSP=0x7fffffffde80",
 "evidence":["$r1"],"quality":{"level":"direct"},"validity":{"state":"active"}}
JSON
#   obs_marker.json: value "[RSP]=0x4141414141414141 attacker marker", evidence=["$r2"] (같은 형식)
#   obs_ret.json:    value "next ret target=0x401234", evidence=["$r3"] (같은 형식)
state event append obs_rsp.json
state event append obs_marker.json
state event append obs_ret.json

# 3) primitive.json: status:"pass", self_evidence=[위 3개 observation_id].
#    input_digest는 SELF evidence가 실제로 측정한 subject_digest(=측정된 ./chal의 sha256)와,
#    environment_digest는 측정 호스트의 tooling-owned digest와 정확히 일치해야 한다(불일치 시
#    PASS는 "must measure the primitive input_digest/environment_digest"로 거부된다).
state primitive --example > primitive.json    # 스캐폴드 → 값 채우기
state primitive pass primitive.json           # revise_primitive가 3xactive+direct SELF invariant + subject/env binding 검증
```

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
