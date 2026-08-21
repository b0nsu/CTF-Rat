# `bin/` 도구 갭 분석과 우선순위

## 결론

이 레포의 방향은 **도구를 많이 모으는 것**이 아니라, 로컬 artifact에서 얻은 관찰을
`fact → hypothesis → primitive PASS → deterministic verify → handoff`로 승격하는 동안
근거와 실행 환경을 잃지 않는 pwn/rev 풀이 kit를 만드는 것이다. 따라서 새 exploit
generator를 추가하는 것보다 현재의 두 도구 계층을 하나의 운영 경로로 정리하는 일이
먼저다.

- 운영 경로: `ctfguard` → `newchal` → `recon`/`revq` → `decomp`/`gdbq` →
  `state` → pwn/rev 검증 도구 → `pkshare`/`writeupcheck`
- 구조화된 실험 경로: `rat-profile`, `rat-slice`, `rat-dyn`, `rat-fuzz`, `rat-heap`,
  `rat-rop`, `rat-runtime`, `rat-vm`, `rat-verify`와 artifact/orchestration 계층
- 공통 안전장치: 단일 active challenge, 로컬 우선, 명시된 단일 endpoint만 허용,
  digest 기반 provenance, heuristic 결과의 자동 승격 금지

즉, **즉시 필요한 것은 새로운 공격 기법 도구가 아니라 통합·가시성 도구 2개**였으며,
현재 `rat-doctor`와 `rat-scenario`로 구현되어 있다. 그 뒤의 분석기 확장은 실제 fixture가
반복해서 빈틈을 입증할 때만 진행한다.

## 현재 커버리지

| 단계 | 이미 있는 기능 | 판정 |
|---|---|---|
| Guard/ingest | `ctfguard`, `ctfpull`, 안전한 archive 처리, `newchal`, `run.json` | 충분 |
| 정적 triage | `recon`, `revq`, `analyze`, `rat-profile`, `rat-slice` | 중복 경로 정리 필요 |
| RE | `decomp` 캐시, `gdbq`, `symsolve`, `vmlift`, Qiling adapter | 핵심 플랫폼에 충분 |
| pwn 측정 | `pwncrash`, `pwnleak`, `pwncalc`, `pwnpayload`, `pwnropcheck` | userland 기본 체인에 충분 |
| 환경 일치 | `libcgate`, Docker 절차, `rat-runtime`, hash/build-id 기록 | 기능은 있으나 진입점 분산 |
| 증거/상태 | legacy `state`와 typed STATE v2, content-addressed artifact store | 강력하지만 사용 경로가 둘 |
| 검증/인계 | `rat-verify`, skeptic gate, `pkshare`, `writeupcheck` | 충분 |
| 회귀검증 | unittest, pwn fixture, rev e2e, orchestration e2e, CI | 폭넓으나 optional capability 진단과 다름 |

`rat-*` 분석기는 의도적으로 experimental이다. 예를 들어 slice는 call-path이지
value-flow proof가 아니고, builtin fuzz는 coverage-guided가 아니며, heap은 완전한 event
trace를 요구하고, VM은 toy semantics만 제공한다. 이 제한은 정직한 설계이므로 일반적인
대형 framework로 성급히 교체하지 않는다.

## 먼저 해결할 비도구 갭

### P0. 하나의 canonical workflow로 문서화

현재 README/SETUP의 주 경로에는 기존 명령만 노출되고 `rat-*`의 profile → artifact digest
→ scenario → verify 흐름은 보이지 않는다. 반대로 구조화 계층은 legacy `state`, `run.json`,
`pwn*` 도구와 언제 연결되는지 사용자가 알기 어렵다.

먼저 아래를 한 페이지의 실행 예제로 고정한다.

1. 어떤 경우에 `recon`/`revq`만 쓰고 어떤 경우에 `rat-profile`로 진입하는가.
2. scenario JSON을 누가 만들며 profile/trace artifact digest를 다음 명령에 어떻게 넘기는가.
3. heuristic artifact가 `state hypothesis`가 되는 명시적 단계와, primitive PASS가 되는
   별도의 SELF 검증 단계.
4. `rat-verify` 결과, typed STATE v2, `pkshare` 사이의 정확한 연결.
5. legacy 도구와 experimental 도구가 같은 사실을 출력할 때의 authoritative source.

또한 remote 정책을 한 문장으로 통일해야 한다. 루트 진입점은 사용자가 명시한 단일
endpoint를 허용하지만 `doctrine/SOLVING.md`는 모든 외부 접속을 범위 밖으로 적고 있다.
이는 새 network 도구로 해결할 문제가 아니라 정책 문서의 모순이다.

### P0. capability와 regression을 분리

`pkselftest`는 회귀검증기로서 적절하지만, optional dependency가 없으면 SKIP하고도 GREEN이
될 수 있다. 그래서 “레포가 망가지지 않았다”와 “이 artifact를 지금 분석할 수 있다”가
같은 출력으로 보인다. 아래 첫 신규 도구가 이 차이를 해결해야 한다.

## 구현된 우선 도구

### P1. `rat-doctor` — artifact별 capability planner

**필요성:** 가장 큰 실사용 갭은 설치 목록이 아니라, 현재 binary/architecture/runtime에
대해 어떤 분석 경로가 실제로 가능한지 한 번에 판단할 수 없다는 점이다.

인터페이스:

```sh
rat-doctor ./chall [--libc ./libc.so.6] [--loader ./ld-linux-x86-64.so.2] \
  [--rootfs ./rootfs] [--format text|json]
```

최소 출력:

- artifact format, architecture, bitness와 host 실행 가능 여부
- `file`, binutils, gdb, Ghidra, angr, pwntools, Qiling, Wine, QEMU의
  `available/degraded/unavailable` 상태와 버전
- supplied libc/loader/rootfs의 존재와 hash
- 가능한 route (`native`, `gdb`, `angr`, `ghidra`, `qemu`, `qiling`, `wine`)와
  각 route의 차단 원인
- 필수 회귀검증 결과와 optional capability 결과의 분리
- 설치 명령을 실행하지 않는 read-only 동작과 machine-readable schema

`pkselftest`를 복제하지 않는다. `pkselftest`는 repository regression을, `rat-doctor`는
현재 challenge의 실행 계획을 답한다. doctor는 binary를 실행하거나 설치를 변경하지 않으며
각 route의 availability와 companion digest를 JSON으로 제공한다.

### P1. `rat-scenario` — scenario 생성·검증·정규화

**필요성:** `rat-dyn`, `rat-runtime`, `rat-verify`, `rat-vm`은 같은 scenario 계약을
소비하지만 사용자는 JSON을 직접 작성해야 한다. schema 파일은 있어도 CLI validation,
canonical digest preview, stdin binary 처리, 실행 전 environment preview가 없다.

인터페이스:

```sh
rat-scenario init --name smoke --stdin-file input.bin --output scenario.json
rat-scenario validate scenario.json
rat-scenario show scenario.json --canonical --digest
```

최소 요구사항:

- `schemas/rat.scenario.v1.json`을 authoritative contract로 사용
- argv/env/cwd/expect/marker의 타입과 cwd 탈출을 실행 전에 검증
- text stdin과 arbitrary byte stdin을 혼동하지 않는 명시적 encoding
- canonical JSON과 scenario digest 표시
- shell을 거치지 않고, network를 열지 않고, validate 자체는 binary를 실행하지 않음

이 도구는 새 분석 능력을 만들지 않지만 profile → dyn → verify의 재현성을 크게 높인다.

## 조건부로만 추가할 도구

### P2. syscall/seccomp 관찰 adapter

`rat-runtime`은 현재 syscall coverage를 제공하지 않는다. fixture에서 “입력은 맞지만
seccomp 또는 syscall ABI 때문에 exploit chain이 실패”하는 사례가 반복될 때,
`strace`와 `seccomp-tools` 출력을 bounded artifact로 바꾸는 adapter를 추가할 가치가 있다.
단, 정책 우회나 자동 chain 생성기는 만들지 않고 local policy 관찰만 제공해야 한다.

### P2. coverage-guided fuzz adapter

현재 builtin `rat-fuzz`는 작은 corpus 반복기이며 스스로 coverage 부재를 보고한다.
AFL++/libFuzzer/honggfuzz adapter는 source 또는 안정적인 persistent harness가 있는 fixture에서
실제 solve time을 줄인다는 회귀 자료가 생길 때만 추가한다. 기본 설치를 무겁게 만들거나
crash를 primitive PASS로 자동 승격해서는 안 된다.

### P2. allocator event collector

`rat-heap`은 event timeline 검증기는 있지만 event 수집기는 아니다. heap fixture에서 수동
GDB 기록이 병목으로 확인되면 glibc version과 symbol availability를 명시하는 bounded collector를
추가한다. 출력은 candidate evidence여야 하며 tcache count/head/fd 및 safe-linking 산식의
실측값을 포함해야 한다.

## 지금 추가하지 말아야 할 것

- 자동 exploit/ROP chain 생성기: primitive gate를 약화하고 기존 `pwnropcheck`/`rat-rop`과 중복된다.
- remote scanner, endpoint discovery, brute-force runner: 레포의 단일 명시 대상 정책과 충돌한다.
- 또 하나의 state database 또는 writeup generator: STATE v2, artifact store, `pkshare`가 이미 있다.
- 범용 decompiler UI: `revq` → `decomp`의 context 절약 전략과 맞지 않는다.
- web/crypto/forensics 도구 묶음: 현재 pwn/rev 집중 범위를 흐린다.
- 도구별 독자 JSON 포맷: 새 출력은 기존 `rat.tool-result/v1` envelope와 artifact digest를 써야 한다.

## 구현 순서와 완료 기준

1. **P0 문서 통합:** canonical happy path 한 개와 legacy/experimental 선택 기준을 문서화한다.
2. **완료 — `rat-doctor`:** native ELF와 dependency-missing 상태를 artifact별로 판정한다.
3. **완료 — `rat-scenario`:** validation, binary stdin, canonical digest, cwd/env negative test와
   `rat-dyn`/`rat-verify`가 소비하는 공통 입력 encoding을 제공한다.
4. **측정:** 실제 challenge 회고에서 `unsupported/dependency`, scenario 오류, syscall,
   coverage, heap trace 때문에 막힌 횟수를 기록한다.
5. **P2 gate:** 같은 종류의 병목이 독립 fixture/challenge에서 두 번 이상 재현될 때만
   해당 adapter를 구현한다.

신규 도구의 공통 완료 조건은 bounded execution, 공통 exit semantics, dependency 누락의
명시적 partial/error, digest provenance, network-free default, heuristic 자동 승격 금지,
unit test와 최소 e2e fixture다.
