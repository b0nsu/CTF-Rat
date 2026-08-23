# ctf-rat — query-first CTF(pwn/rev) runtime

> 이 저장소는 제공된 CTF artifact와 사용자가 명시한 단일 remote endpoint를 분석·검증하는 pwn/rev 풀이 kit다.
> **기본 목표는 가장 짧은 결정적 분석 경로로 실제 verifier/flag까지 도달하는 것**이다. 문서·지식·서브에이전트는 필요할 때만 로드한다.

## 1. 하드 불변식

- **범위**: 제공된 binary/source/libc/rootfs/Docker/loopback이 기본이다. 사용자가 대화에서 명시한 **단일 host:port/SSH endpoint**만 접속·exploit 전송·flag 수신 가능하다.
- 사용자 지정이 없는 대상 탐색, 스캔, 무차별 대입, 자격증명 수집, 지속성, 탐지 회피, 데이터 삭제·유출, DoS는 금지한다.
- **honest-mode**: 실제 실행/응답 증거 없이 `SOLVED`, remote 성공, shell/flag 획득을 주장하지 않는다.
- **활성 문제 1개**: 시작 시 `ctfguard begin <challenge> [target]`; 전환 전 `ctfguard finish blocked|complete`.
- **git push/merge는 사람만**: 사용자가 명시적으로 요청한 경우에만 저장소 변경을 publish한다.
- heuristic 결과는 사실/primitive로 자동 승격하지 않는다. artifact digest와 실행 환경을 보존한다.

## 2. 기본 실행 경로 — FAST

**세션 시작 시 doctrine 전체를 먼저 읽지 않는다.** 먼저 challenge를 직접 triage한다.

1. `ctfguard check`로 active challenge를 확인한다. 미초기화면 `ctfguard begin` 후 `newchal`을 사용한다.
2. 환경 불확실성이 있으면 `rat-doctor <bin> --format json`으로 가능한 native/GDB/angr/Ghidra/QEMU/Qiling/Wine route만 확인한다.
3. pwn은 `recon <bin>`, rev는 `revq <bin>`으로 시작한다.
4. **raw dump보다 bounded query를 우선**한다.
   - rev: `revq --interesting`, `revq --func <candidate>`, `revq --xrefs <target>`
   - decompile은 필요한 함수만 `decomp <bin> <func>`
   - 동적 관찰은 목적이 명확할 때 `gdbq`, `rat-dyn`, pwn 측정 도구를 사용한다.
5. 가장 가능성 높은 가설 하나를 최소 실험으로 검증한다.
6. 로컬 executable oracle/verifier가 명확하면 실제 binary를 재실행해 성공 여부를 확인한다.
7. 결정적 검증이 PASS면 종료한다. 불확실성·실패 조건이 생길 때만 DEEP으로 승격한다.

### FAST에서 기본적으로 하지 않는 것

- `SOLVING.md`, `SOLVABILITY.md`, `PRIMITIVE_GATE.md`, `GROUNDING_INDEX.md` 전체 선로딩
- 전체 Ghidra decompile/전체 CFG/전체 STATE history 읽기
- 큰 정적 읽기라는 이유만으로 무조건 subagent 생성
- 모든 문제에서 2~3-way hypothesis fan-out
- deterministic verifier가 이미 PASS한 단순 rev에서 추가 LLM skeptic 실행
- 같은 `strings`/`revq`/decomp/CFG 분석 반복

## 3. DEEP 승격 조건

다음 중 하나면 필요한 문서·지식만 lazy-load하고 DEEP으로 전환한다.

- 서로 독립적인 유효 가설이 2개 이상 남음
- FAST probe가 반복 실패하거나 새 사실/배제/primitive 진전이 없음
- remote/local 환경 차이가 exploit 안정성에 영향
- heap/kernel/complex ROP/format-string chain 등 primitive 증명이 핵심
- VM/packing/anti-debug/heavy obfuscation 때문에 정적 결과 신뢰가 낮음
- symbolic path explosion, indirect control flow, aliasing 등으로 bounded 분석이 불충분
- 증거끼리 충돌하거나 SOLVED 주장을 반증할 필요가 있음

DEEP에서만 필요에 따라 읽는다:

- `doctrine/SOLVING.md` — 전체 solve/reproduction 규약
- `doctrine/SOLVABILITY.md` — route가 실제로 성립하는지 점검
- `doctrine/PRIMITIVE_GATE.md` — pwn primitive 승격 계약
- `knowledge/GROUNDING_INDEX.md` — 유형별 지식 하나를 선택하는 router
- `doctrine/WRITEUP_FORMAT.md` — 검증 완료 후 문서화 시

## 4. pwn primitive / correctness gate

pwn에서 exploit chain은 검증된 primitive를 기반으로 한다.

```text
observation/fact
  → hypothesis
  → minimal SELF experiment
  → primitive PASS
  → exploit composition
  → deterministic/local or authorized-remote verification
```

- 후보는 `state hypothesis ...` 또는 typed STATE finding으로 기록한다.
- RIP/EIP/control marker/leak/AAW 등 주장한 primitive를 실제 최소 payload로 확인하기 전 최종 chain의 근거로 쓰지 않는다.
- `state primitive ... pass ...`/typed primitive PASS는 관련 evidence가 active일 때만 유효하다.
- libc/loader/runtime mismatch가 있으면 remote-equivalent로 간주하지 않는다.

단순 rev checker처럼 exploit primitive 개념이 없는 문제는 **candidate input → 실제 binary 실행 → success oracle**이 더 강한 검증이다. 이 경우 불필요한 pwn primitive 절차를 억지로 적용하지 않는다.

## 5. 컨텍스트 정책

- 모델 context에는 **현재 판단에 필요한 projection만** 둔다.
- `STATE.jsonl`/STATE v2는 영구 evidence bus이지 대화 context가 아니다. 기본은 `state show`, `state compact`, `state delta`의 bounded view를 사용한다.
- 큰 raw output은 artifact/cache에 남기고, 필요한 함수/주소/범위만 다시 질의한다.
- 동일 입력·도구·파라미터의 결정적 분석은 cache 결과를 우선 재사용한다. stale/partial/truncated 결과는 재사용하지 않는다.
- 한 도구를 다시 실행하기 전 **새 정보가 생겼는지** 확인한다. 같은 fingerprint의 반복 호출은 원칙적으로 피한다.

## 6. Subagent 정책

서브에이전트는 context 자체가 아니라 **독립적인 추론/읽기 작업**이 실제 병목일 때만 사용한다.

- bounded query/결과가 대략 2k tokens 이하 → main agent가 직접 처리
- 대형 decompile/raw 자료를 반드시 읽어야 함 → scout 1개로 요약
- 유효한 상충 가설이 2개 이상 → hypothesis fan-out 기본 2, 최대 3
- pwn remote/environment-sensitive 최종 검증 → skeptic 1개 권장
- executable oracle이 명확히 PASS한 단순 rev → skeptic 생략 가능

서브에이전트 결과도 미검증 해석은 hypothesis이며 사실로 자동 승격하지 않는다.

## 7. 기존 도구 hot path

```text
GUARD     ctfguard
INGEST    newchal / ctfpull
CAP       rat-doctor
PWN       recon → pwncrash/pwnleak/pwncalc/pwnpayload/pwnropcheck → rat-verify
REV       revq → decomp(필요 함수만) → symsolve(concrete verify) / rat-dyn
STATE     state (STATE v2 우선)
ARTIFACT  rat-* structured analysis + content-addressed store
HANDOFF   pkshare / writeupcheck
```

`revq`는 큰 함수/문자열/xref 분석을 컨텍스트 밖에서 캐시하고 `--func` 등으로 필요한 카드만 회수하는 것이 기본 사용법이다.

## 8. 정체/재계획 규칙

연속된 probe에서 다음이 하나도 바뀌지 않으면 현재 route를 반복하지 말고 재계획한다.

- 새 direct observation/fact
- hypothesis refute/confirm
- primitive 상태 변화
- 새 oracle/target address 발견
- 환경 불확실성 해소

그때만 더 깊은 decompile, symbolic solve, 동적 tracing, knowledge lookup 또는 subagent를 사용한다.

## 9. 완료 조건

`SOLVED`는 다음 중 실제 증거가 있을 때만 선언한다.

- rev: candidate가 실제 challenge binary의 success oracle을 통과
- pwn local: 의도된 효과/flag가 동일 binary+libc/loader/runtime에서 재현
- authorized remote: 사용자가 지정한 endpoint에서 실제 응답으로 의도된 효과/flag 수신

flag 문자열 추측, heuristic score, decompiler 해석, symbolic candidate만으로는 완료가 아니다.

검증 후에만 필요하면 `pkshare`/`writeupcheck`로 인계·문서화한다.
