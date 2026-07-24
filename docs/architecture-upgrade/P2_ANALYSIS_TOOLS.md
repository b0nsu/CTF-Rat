# P2 — 분석 정확도 및 신규 `rat-*` 도구

> 상태: `implemented` (MVP). artifact-gated core 흐름과 angr CFG/VEX IR slice는 구현되었다.
> Ghidra p-code 수준의 정밀 taint와 완전한 GDB/MI backend는 정확도 고도화 항목으로 후속 작업이다.

## 1. 목표와 비목표

### 목표

- profile → slice/dynamic analysis → concrete verify의 순서를 도구 계약으로 고정한다.
- `rat-slice`, `rat-dyn`, `rat-verify`, `rat-fuzz`, `rat-heap`, `rat-rop`, `rat-runtime`, `rat-vm`의
  최소 유용 CLI와 artifact를 구현한다.
- `rat-profile` 및 기존 `recon`/`analyze`의 출력을 fact, signal, route로 분리한다.
- timeout과 선택 dependency 부재에서도 검증 가능한 부분 결과를 보존한다.
- 각 category를 synthetic text가 아니라 실제 실행 가능한 fixture로 e2e 검증한다.

### 비목표

- 범용 decompiler/debugger/fuzzer를 새로 작성하는 것. 기존 angr/Ghidra/GDB/QEMU/Qiling/AFL 계층을 감싼다.
- signal을 취약점 fact로 자동 승격하거나 exploit을 자동 원격 실행하는 것.
- 모든 아키텍처와 파일 형식을 v1에서 지원하는 것.
- 멀티에이전트 배치 정책(P3 범위)과 KPI 승인(P4 범위).

## 2. 선행조건과 완료 후 보장사항

### 선행조건

- [P1 완료 기준](P1_DATA_CONTRACTS.md#9-완료-기준)을 충족한다.
- 모든 입력은 artifact digest 또는 digest가 계산된 local path로 식별된다.
- 모든 도구가 P0 runner와 `rat.tool-result/v1`을 사용한다.
- finding/primitive 승격은 STATE v2 validator를 통과한다.

### 완료 후 보장사항

- heuristic ranking과 직접 관측이 구조적으로 구별된다.
- timeout 결과도 어떤 함수/경로/iteration까지 분석했는지 알 수 있다.
- `rat-verify`가 재현하지 못한 claim은 confirmed finding이나 primitive PASS가 될 수 없다.
- 각 도구의 결과는 raw stdout 없이 다음 도구의 입력으로 사용할 수 있다.
- 기존 `recon`/`analyze` 사용자는 텍스트 UI를 유지하면서 새 schema로 점진 migration할 수 있다.

## 3. PDF 백로그 ID 매핑

| ID | 도구 | 책임 |
|---|---|---|
| B014 | `rat-slice` | source/sink 기준 bounded static slice와 경로 조건 |
| B015 | `rat-dyn` | scenario 기반 trace, register/memory observation |
| B016 | `rat-verify` | claim/primitive의 executable oracle 검증 |
| B017 | `rat-fuzz` | bounded coverage/crash discovery와 reproducible testcase |
| B018 | `rat-heap` | allocator event와 bin/safe-linking invariant 분석 |
| B019 | `rat-rop` | gadget/constraint/chain feasibility 분석 |
| B020 | `rat-runtime` | native/QEMU/Qiling 실행 환경과 provenance 통일 |
| B021 | `rat-vm` | custom VM dispatch/opcode/trace/lift 보조 |

`rat-profile`은 B014~B021의 공통 선행 작업이며 기존 `recon`/`analyze` 정합성 개선을 포함한다.

## 4. 구현 작업 단위와 내부 의존성

```text
rat-profile
   ├─────────────► rat-slice ─┐
   └─────────────► rat-dyn ───┼─► rat-verify
                              │
independent extension bundles │
   rat-fuzz ──────────────────┤
   rat-heap ──────────────────┤
   rat-rop ───────────────────┤
   rat-runtime ───────────────┤
   rat-vm ────────────────────┘
```

core 경로의 완료 순서는 **profile → slice/dyn → verify**로 고정한다. heap/ROP/runtime/VM은 서로를
선행조건으로 만들지 않는 독립 확장 묶음이며, 각자 profile envelope만 공통 입력으로 받는다. fuzz finding은
verify로 수렴한다.

### P2.0 — `rat-profile`과 fact/signal/route 분리

최소 CLI:

```text
rat-profile BIN [--libc LIBC] [--loader LD] [--timeout SEC]
            [--format text|json] [--store DIR]
```

- **fact:** ELF class/arch/endianness, entry/load base, NX/PIE/RELRO/canary, imported symbol, string 위치처럼
  직접 parse한 observation. evidence locator가 필수다.
- **signal:** dangerous API 존재, sparse bounds check, VM-like dispatch, win-like symbol처럼 heuristic 점수.
  detector ID/version, score, false-positive note를 포함한다.
- **route:** 다음에 실행할 도구와 좁은 target을 제안한다. 예: `rat-slice --from input --to memcpy`.
  route는 finding이나 primitive가 아니다.

기존 `recon`의 보호기법은 fact, `SINK`/`VM?`는 signal, `TRIAGE`와 "다음"은 route로 옮긴다. 기존
`analyze`의 graph+1-hop 점수는 signal이며 함수 순위가 취약점 확정으로 렌더되지 않게 한다.

profile summary 필수값: format/arch/protections, function count의 exactness, fact/signal/route count,
coverage, skipped analyzers. artifact: `profile.json`, `function-index.json`, `string-index.json`, 선택적 raw tool log.

### 도구별 최소 계약

아래 모든 도구는 공통으로 `--timeout`, `--max-output`, `--format text|json`, `--store`, `--no-cache`를
지원한다. JSON은 stdout에 envelope 하나만 출력한다. text mode도 같은 envelope를 artifact store에 남긴다.

| 도구 | 최소 CLI/입력 | envelope summary | artifact kind | partial/timeout 표현 |
|---|---|---|---|---|
| `rat-slice` | `BIN --from LOC [--to LOC] [--direction back|forward] [--depth N]`; profile digest, symbol/address/finding | nodes/edges, sources/sinks reached, path count, coverage, unresolved indirect edges | `static-slice`, `cfg-fragment`, `path-constraints`, `decomp-snippet` | 방문 block/queue 잔량, unresolved target, continuation frontier |
| `rat-dyn` | `BIN --scenario FILE [--break LOC] [--watch EXPR]`; runtime inputs | exit/signal, trace span, hit counts, register/memory observation 수 | `execution-trace`, `register-snapshot`, `memory-snapshot`, `io-transcript` | 마지막 PC/event, dropped event 수, scenario step |
| `rat-verify` | `BIN --claim FINDING_ID|--primitive SPEC --scenario FILE [--oracle FILE]` | verdict(`pass/fail/inconclusive`), repetitions, environment match, failed conditions | `verification-report`, `minimal-input`, `core-evidence`, `oracle-transcript` | timeout은 `inconclusive`; 충족/미충족 condition 분리 |
| `rat-fuzz` | `BIN --harness FILE --budget SEC [--corpus DIR] [--engine ENGINE]` | execs, coverage, unique crash/hang, corpus delta | `fuzz-corpus`, `coverage-map`, `crash-input`, `crash-signature` | budget 종료는 정상 partial, reproducer 미확인은 finding proposed만 |
| `rat-heap` | `BIN (--scenario FILE|--trace DIGEST) [--libc LIBC]` | allocator/version, event/bin count, invariant violations, ambiguity | `heap-timeline`, `bin-snapshot`, `safe-linking-check`, `allocation-graph` | 빠진 hook/event 범위와 신뢰할 수 없는 interval |
| `rat-rop` | `BIN --goal call|orw|pivot [--constraints FILE] [--primitive ID]` | gadget count, satisfiable constraints, bad-byte/stack effects, candidate count | `gadget-index`, `chain-candidate`, `constraint-report` | incomplete scan 영역; candidate는 exploit success가 아님 |
| `rat-runtime` | `BIN --backend native|qemu|qiling --scenario FILE [--rootfs DIR]` | backend/version, guest arch, environment digest, exit, syscall coverage | `runtime-manifest`, `syscall-trace`, `filesystem-diff`, `execution-trace` | 마지막 PC/syscall, unsupported syscall, rootfs gap |
| `rat-vm` | `BIN (--dispatch LOC|--trace DIGEST) [--bytecode FILE] [--solve]` | dispatcher confidence, opcode count, lifted count, unknown opcode, solve candidates | `opcode-table`, `vm-trace`, `lifted-ir`, `vm-model`, `candidate-input` | unknown opcode/semantics 목록, trace coverage, 미검증 candidate |

### P2.1 — B014 `rat-slice`

- angr CFG와 decomp index를 입력으로 하되 backend별 결과를 observation으로 분리한다.
- indirect call, self-modifying region, timeout frontier를 숨기지 않는다.
- slice node는 binary digest + normalized address + statement index로 안정 ID를 만든다.
- heuristic source/sink는 signal이고, 실제 data/control dependency edge만 fact다.

### P2.2 — B015 `rat-dyn`

- scenario는 argv/env/stdin/file/menu action과 예상 종료 조건을 선언한 versioned YAML/JSON이다.
- ASLR, loader, libc, cwd, locale, env allowlist를 runtime manifest에 기록한다.
- memory snapshot은 요청 범위만 저장하고 `/proc` 전체나 secret 환경을 수집하지 않는다.
- trace event hard cap과 sampling 여부를 summary에 기록한다.

### P2.3 — B016 `rat-verify`

- finding claim은 assertion 목록으로 compile한다. 예: RIP marker, allocation return target, recovered input의 success exit.
- 최소 payload, 일반 실행/core 또는 remote-equivalent, register/marker/terminator 조건을 검사한다.
- rev candidate는 실 binary executable oracle로 재실행한다. 문자열 발견이나 solver sat만으로 pass하지 않는다.
- verdict pass만 confirmed finding/primitive PASS 요청을 생성한다. validator가 최종 승격한다.

### P2.4 — B017 `rat-fuzz`

- 기본은 로컬 executable fixture만 대상으로 하고 네트워크 fuzz는 지원하지 않는다.
- crash는 signal/stack/PC/coverage를 정규화해 dedup하고, 최소화 후 3회 재현한다.
- testcase, harness, binary/runtime digest가 모두 있어야 finding을 만들 수 있다.
- budget 소진은 error가 아니라 `partial`; engine crash는 `error`다.

### P2.5 — B018 `rat-heap`

- malloc/free/realloc event를 동일 sequence ID로 묶고 tcache count/head/next 반환 순서를 직접 기록한다.
- safe-linking은 실측 chunk/target로 `encoded_fd == target ^ (chunk >> 12)`를 계산해 observation을 만든다.
- glibc/loader provenance가 없으면 version-sensitive 결론을 confirmed로 만들지 않는다.
- trace에 gap이 있으면 gap을 가로지르는 heap invariant는 unknown이다.

### P2.6 — B019 `rat-rop`

- gadget index와 feasibility 분석을 분리한다. candidate chain은 finding/primitive가 아니다.
- exploit-oriented `--primitive`는 registry의 active PASS만 받는다. 없으면 code 5와 필요한 evidence를 반환한다.
- ABI alignment, clobber, bad bytes, readable/writable/executable mapping, seccomp constraints를 report한다.
- gadget 주소는 binary digest와 load-relative offset으로 저장하고 live base를 추측하지 않는다.

### P2.7 — B020 `rat-runtime`

- native/QEMU/Qiling의 공통 scenario와 runtime manifest를 제공한다.
- backend/rootfs/kernel emulation 차이를 provenance에 넣고 서로를 같은 환경으로 취급하지 않는다.
- P0 Qiling timeout과 target/network policy를 그대로 사용한다.
- filesystem diff는 runner staging 아래만 관찰하고 host 전체를 비교하지 않는다.

### P2.8 — B021 `rat-vm`

- dispatch 후보 → trace opcode → opcode table → lifted semantics → candidate solve 순서로 실행한다.
- opcode 의미는 direct trace, derived semantics, heuristic guess를 분리한다.
- `--solve` 결과는 candidate일 뿐이며 반드시 `rat-verify` executable oracle로 보낸다.
- unknown opcode가 success path에 있으면 complete lift나 solve를 선언하지 않는다.

## 5. CLI·schema·파일 레이아웃 변경

```text
bin/rat-profile
bin/rat-slice
bin/rat-dyn
bin/rat-verify
bin/rat-fuzz
bin/rat-heap
bin/rat-rop
bin/rat-runtime
bin/rat-vm
bin/ratlib/analysis/
schemas/rat.scenario.v1.json
schemas/rat.verification-report.v1.json
tests/fixtures/analysis/{profile,slice,dyn,verify,fuzz,heap,rop,runtime,vm}/
```

도구 간에는 local path가 아니라 artifact digest와 finding/primitive ID를 넘긴다. 사용자가 path를 주면 CLI가
먼저 artifact store에 넣고 envelope에는 digest를 기록한다.

## 6. 하위 호환성 및 migration

- `recon`은 당분간 기존 text renderer로 `rat-profile`을 호출한다. 결과 문구와 순서는 snapshot test로 보호한다.
- `analyze`는 legacy `.decomp`를 읽을 수 있지만 ranking을 `SIGNAL`로 표시하고 `--format json`은 새 envelope다.
- `revq`, `decomp`, `gdbq`, `symsolve`, `vmlift`는 제거하지 않는다. 새 도구가 이들을 backend로 사용하거나
  artifact importer를 제공한다.
- 기존 exploit/scenario 스크립트는 실행 가능하지만 cache와 verified 승격에는 versioned scenario가 필요하다.
- deprecated CLI는 최소 한 minor cycle 경고 후 제거 여부를 별도 결정한다.

## 7. 실패 모드와 보안 조건

| 실패 모드 | 요구 동작 |
|---|---|
| CFG/decompile 불완전 | coverage와 unresolved edge를 partial로 기록 |
| trace cap/timeout | 마지막 안정 cursor와 dropped 범위 보존 |
| verify oracle 불명확 | `inconclusive`; pass/fail 추측 금지 |
| fuzz non-repro crash | proposed signal만 생성, confirmed 금지 |
| wrong libc/rootfs/backend | environment mismatch diagnostic, primitive stale |
| ROP primitive 없음 | candidate scan은 가능, exploit chain build는 code 5로 거부 |
| VM unknown opcode | lift/solve partial, executable verify 전 승격 금지 |
| tool schema invalid | P1 quarantine, downstream 입력 금지 |
| network 요청 | `ctfguard-target` 통과 전 실행 금지; fuzz network mode 없음 |

분석 대상이 악성 동작을 할 수 있으므로 동적 도구는 P0 resource/network/filesystem policy 안에서만 실행한다.
core/memory artifact의 secret 가능성을 metadata에 표시하고 기본 export를 금지한다.

## 8. 테스트 fixture와 실행 명령

모든 fixture는 source, build recipe, compiler/runtime digest, expected intermediate ground truth를 포함한 실행 파일이다.

- profile: 보호기법 조합, stripped/PIE, alias symbol, unsupported format.
- slice: direct/indirect data flow, unreachable sink, loop, timeout frontier.
- dyn/verify: stdin marker RIP, terminator 파손, ASLR 환경 차이, success/failure oracle.
- fuzz: deterministic crash/hang, duplicate signature, non-repro crash.
- heap: tcache order, safe-linking correct/incorrect encoding, trace gap.
- ROP: alignment/bad-byte/clobber, seccomp ORW constraint, primitive missing.
- runtime: native와 QEMU/Qiling 동일 toy semantics, unsupported syscall, missing rootfs.
- VM: 알려진 opcode table, unknown opcode, candidate input과 concrete oracle.

구현 후 실행 명령:

```sh
python3 -m unittest tests.test_p2_analysis
python3 tests/e2e_analysis.py --category core
python3 tests/e2e_analysis.py --category heap
python3 tests/e2e_analysis.py --category rop
python3 tests/e2e_analysis.py --category runtime
python3 tests/e2e_analysis.py --category vm
bash tests/e2e_rev.sh
```

## 9. 완료 기준

- [x] `rat-profile`이 fact/signal/route를 schema와 text 양쪽에서 분리한다.
- [x] B014~B021 각 CLI가 valid envelope, bounded summary, documented artifact를 만든다.
- [x] 모든 도구가 timeout/partial/missing dependency fixture에서 공통 의미를 지킨다.
- [x] core 흐름이 profile → slice/dyn → verify 순서를 기계적으로 강제한다.
- [x] verify pass 외에는 confirmed finding/primitive PASS를 생성하지 않는다.
- [x] ROP exploit mode가 active verified primitive 없는 입력을 거부한다.
- [x] rev/VM candidate가 실 binary executable oracle을 통과해야 solve evidence가 된다.
- [x] category별 executable fixture e2e가 핵심 중간 결과를 확인한다.
- [x] raw stdout은 artifact로 보존하고 envelope summary만 다음 도구에 전달한다.
- [x] 기존 recon/analyze/revq/decomp/symsolve/vmlift smoke test를 회귀 검증한다.

## 10. 권장 커밋 분할

1. `feat: split profile facts signals and routes`
2. `feat: add bounded static slicing`
3. `feat: add scenario-based dynamic traces`
4. `feat: verify findings against executable oracles`
5. `feat: add bounded fuzz and reproducible crash artifacts`
6. `feat: model heap traces and allocator invariants`
7. `feat: report ROP feasibility from verified primitives`
8. `feat: unify native qemu and qiling runtimes`
9. `feat: trace and lift custom VM bytecode`
10. `test: add executable analysis category e2e`

## 11. 진행 체크리스트

- [x] `rat-profile` migration
- [x] B014 `rat-slice`
- [x] B015 `rat-dyn`
- [x] B016 `rat-verify`
- [x] B017 `rat-fuzz`
- [x] B018 `rat-heap`
- [x] B019 `rat-rop`
- [x] B020 `rat-runtime`
- [x] B021 `rat-vm`
- [x] category e2e
- [x] [완료 기준](#9-완료-기준) 전체 확인
