# P0 — 안정성 및 코드·문서 정합성

## 1. 목표와 비목표

### 목표

- archive 수집, 외부 프로세스 실행, selftest, `run.json`, decompile cache를 신뢰 가능한 기반으로 만든다.
- 모든 도구가 공통 종료 코드와 timeout 의미를 사용하고 partial 결과를 숨기지 않게 한다.
- 현재 작업 중인 `ctfguard`, primitive gate, Docker/libc provenance, decomp fallback 변경을 먼저 검증해
  기준점을 고정한다.
- 코드가 보장하지 않는 동작을 README/doctrine에서 약속하지 않도록 정합성 검사를 추가한다.

### 비목표

- STATE v2나 content-addressed artifact store 구현(P1 범위).
- 새로운 정적·동적 분석 알고리즘(P2 범위).
- 멀티에이전트 scheduler나 benchmark 판정(P3/P4 범위).
- archive 안의 실행 파일을 자동 실행하거나 원격 target을 자동 탐색하는 기능.

## 2. 선행조건과 완료 후 보장사항

### 선행조건

1. 현재 저장소 변경을 섞지 않도록 `git status --short`와 `git diff --stat`을 보존한다.
2. **도구 전용 checkpoint**를 별도 branch/worktree 또는 명시적으로 stage한 파일 집합으로 만든다.
   기존 challenge 산출물과 unrelated 수정은 stage하지 않는다. 커밋은 사람의 명시 요청이 있을 때만 한다.
3. 공유 `.gitignore`를 먼저 정리해 `ACTIVE.json*`, `.rat/`, decomp/cache, core, 다운로드 staging,
   credential 파일이 이후 커밋에 섞이지 않게 한다. 추적 중인 fixture는 좁은 `!` 규칙으로만 예외 처리한다.
4. 기준 selftest 결과와 선택 dependency 목록을 기록한다.

권장 checkpoint 확인 명령:

```sh
git status --short
git diff -- .gitignore CLAUDE.md SETUP.md doctrine bin tests reference
git diff --check
```

### 완료 후 보장사항

- 신뢰할 수 없는 archive는 staging 경계 밖에 쓰거나 링크·device를 만들 수 없다.
- 모든 bounded subprocess는 wall timeout, 출력 한도, 종료 원인을 같은 방식으로 보고한다.
- selftest는 하나라도 실패·timeout이면 non-zero로 종료한다.
- manifest와 decomp cache는 content/provenance가 달라지면 stale 결과를 재사용하지 않는다.
- 선택 dependency가 없어도 명확한 `dependency_missing` 또는 `partial` 결과를 내며 hang하지 않는다.

## 3. PDF 백로그 ID 매핑

| ID | 작업 | 구현 결과 |
|---|---|---|
| B001 | safe archive | `ratlib.safe_archive`와 malicious archive fixture |
| B002 | 공통 subprocess wrapper | list argv, timeout/exit/stdout/stderr/tool version 기록과 중복 wrapper 통합 |
| B003 | selftest exit | 집계 실패·skip·timeout 종료 의미 통일 |
| B004 | `newchal` manifest | slug/root 검증, `--run` staging→solve merge, solve 단일 owner |
| B005 | decomp cache | hash 기반 cache key, stale/partial/fallback 분리 |
| B006 | `revq` count | schema v2의 instruction/block count 분리 |
| B007 | Qiling hook/stop | instruction hook 명칭 정정, `emu_stop()`과 wall-timeout process kill |

## 4. 구현 작업 단위와 내부 의존성

```text
checkpoint + .gitignore
 ├─ B002 common runner ─┬─ B003 selftest
 │                      ├─ B005 decomp
 │                      └─ B007 Qiling
 ├─ B001 safe archive ───── B004 staging manifest
 └─ B006 revq schema / B007 Qiling stop (독립)
```

### P0.0 — checkpoint와 ignore 정리

- `git status --porcelain=v2`를 CI/job artifact로 남기고 P0 대상 파일 목록을 고정한다.
- `.gitignore`는 로컬 실행 산출물만 공유 규칙으로 추가한다. 기존 사용자 파일을 삭제하거나 untrack하지 않는다.
- `ACTIVE.json` archive, `.rat/`, `*.decomp/`, `core`, `core.*`, extraction staging, `.ctfd.env`를 점검한다.

### P0.1 — B001 safe archive

- ZIP/TAR 계열을 한 API로 검사한 뒤 목적지 내부의 격리된 임시 디렉터리에 전부 추출한다. 전체 검증과 충돌
  preflight가 성공한 뒤에만 top-level entry를 `os.replace`로 공개한다.
- member 이름은 `PurePosixPath`로 해석한다. absolute path, drive/UNC prefix, 빈 이름, NUL,
  `.`/`..` segment, staging 밖으로 resolve되는 경로를 거부한다.
- symlink, hardlink, FIFO, socket, block/char device를 거부한다. ownership, xattr, setuid/setgid/sticky bit는
  복원하지 않는다. regular file과 directory만 허용한다.
- 기본 한도는 member 4,096개, member당 256 MiB, 총 uncompressed 1 GiB, 압축 팽창비 100:1,
  archive nesting 2단계다. policy 파일은 이 한도를 낮추는 것만 허용한다.
- 파일명은 shell command로 재조립하지 않는다. Unicode normalization으로 서로 다른 이름을 합치지 않으며,
  정확히 동일한 destination은 거부한다.
- CRC/stream 길이를 실제 추출 중 다시 확인한다. 검사 시 header 값만 믿지 않는다.

### P0.2 — B002 공통 subprocess runner

`ratlib.runner.run(spec)` 하나로 Python과 shell 도구 실행을 모은다.

- `shell=False`, argv 배열, 명시적 cwd, 최소 환경 allowlist를 기본값으로 한다.
- 새 process group/session에서 실행하고 wall timeout 시 `SIGTERM`, 1초 grace 뒤 `SIGKILL`한다. 자식까지 회수한다.
- Linux에서 기본 제한을 적용한다: CPU 60초, address space 2 GiB, file size 512 MiB, open files 256,
  processes 64, core 0. 도구 profile이 더 낮은 값을 지정할 수 있다.
- stdout/stderr는 각각 8 MiB에서 spool artifact로 전환하고, 64 MiB hard cap 이후 truncate한다. truncation은
  결과에 반드시 표시한다.
- 네트워크 정책은 로컬 도구용 `inherit`, target preflight가 필요한 `ctfguard-target`, 격리 요청인 `none`을 구분한다.
  현재 backend가 network namespace를 제공하지 않으므로 `none`은 격리를 가장하지 않고 fail-closed한다.
- 취소·timeout 후 orphan process가 없음을 검증한다.

공통 process exit code:

| code | 의미 |
|---:|---|
| 0 | 유효한 결과. 완전/부분 여부는 구조화 결과의 `status`로 판별 |
| 2 | CLI 또는 schema validation 오류 |
| 3 | 필수 dependency 없음 |
| 4 | input 없음·손상·지원하지 않는 형식 |
| 5 | ROE/guard/policy 거부 |
| 70 | 도구 내부 오류 |
| 124 | wall/resource timeout |
| 130 | 사용자·오케스트레이터 취소 |

signal 종료는 envelope에 signal을 별도로 기록하고 shell-facing code는 `128 + signal`을 보존한다. P1 전까지
legacy tool은 stderr 마지막 줄에 `RAT_STATUS=<status> RAT_EXIT=<code>`를 출력할 수 있다.

### P0.3 — B003 selftest exit

- test case를 pass/fail/skip/timeout으로 집계한다.
- 필수 case의 fail/timeout, test harness 내부 오류, case 0개 발견은 non-zero다.
- optional dependency 부재로 명시된 skip만 성공을 막지 않는다. `STRICT_OPTIONAL=1`이면 skip도 실패다.
- trap으로 임시 디렉터리와 child process를 정리하며, 요약을 출력한 뒤 실제 집계 code로 종료한다.

### P0.4 — B004 manifest

- `newchal`은 안전한 ASCII basename slug만 받고, symlink destination과 solve root 밖 경로를 code 5로 거부한다.
- `ctfpull`은 `newchal ... --run <staging/run.json>`을 호출한다. `newchal`은 같은 `run_id`와 ingest 사용자 필드를
  보존하면서 `solve/<slug>/run.json`을 atomic하게 materialize하고 `manifest_owner.kind=solve`를 기록한다.
- 기존 solve manifest와 incoming manifest의 `run_id`가 다르면 덮어쓰지 않는다.
- `run.json`은 임시 파일 write → fsync → rename으로 갱신하고 schema validation 실패 시 기존 파일을 보존한다.
- 최소 필드: schema(`rat.run/v1`), run ID, challenge ID/name/category, created time, 입력별 SHA-256/size,
  binary/libc/loader 역할, target allowlist의 비밀 없는 표현, tool/dependency version, 실행 policy, status다.
- token, flag, cookie, 전체 원격 banner는 기록하지 않는다. target은 guard가 허용한 host:port만 기록한다.
- P1이 schema를 정식 소유한다. P0 구현은 동일 이름과 필드를 사용해 이중 migration을 피한다.

### P0.5 — B005 decomp cache

- cache key는 binary SHA-256, Ghidra version, analyzer/project options, export script hash로 계산한다.
  mtime이나 basename만 사용하지 않는다.
- `_index`에는 key, 생성 완료 여부, 함수 총수/내보낸 수, 실패 함수, diagnostics를 기록한다.
- cache는 완료 marker가 있고 key가 정확히 일치할 때만 hit다. 중단된 디렉터리는 `partial`로 읽을 수 있지만
  완전 cache처럼 취급하지 않는다.
- revq 주소 alias → Ghidra 주소 변환은 load base 근거를 기록한다. exact decompile이 없을 때 disassembly fallback을
  사용하되 출력 머리말과 status에 `fallback`을 명시한다.

### P0.6 — B006 revq instruction/block count

- revmap schema를 v2로 올리고 각 함수에 `nblocks`, `ninstr`, `count_quality`를 별도 필드로 둔다.
- angr에서는 `nblocks=len(function.blocks)`, `ninstr=sum(block.instructions)`로 계산한다. binutils fast tier는
  값을 추측하지 않고 둘 다 0, quality `unavailable`로 표시한다.
- 함수 카드와 목록 heading에서도 block과 instruction을 서로 다른 label로 출력한다.
- 함수 total/visible/filtered/truncated 및 alias count는 별도 display metadata로 유지한다.

### P0.7 — B007 Qiling timeout

- Qiling은 B002 runner 안에서 실행하며 wall/CPU/memory/instruction budget을 받는다.
- `hook_code` 결과는 call trace가 아니라 instruction event/count로 명명한다. instruction budget 도달 시
  hook이 `ql.emu_stop()`을 호출하고 code 124를 반환한다.
- wall timeout은 Qiling process group을 TERM→KILL하고 마지막 checkpoint의 PC/count를 partial 결과로 남긴다.
- Qiling/rootfs가 없으면 code 3과 설치 힌트를 반환한다. native fallback을 몰래 실행하지 않는다.

## 5. CLI·schema·파일 레이아웃 변경

최소 CLI:

```text
ctfpull ... [--archive-policy FILE] [--no-extract]
newchal NAME BIN [LIBC] [HOST:PORT] [--run staging/run.json]
decomp BIN [FUNC] [--refresh] [--timeout SEC] [--format text|json]
revq BIN ... [--json]
rat-qiling BIN --rootfs DIR [--timeout SEC] [--instruction-budget N]
pkselftest [--strict-optional] [--format text|json]
```

내부 모듈과 fixture:

```text
bin/ratlib/runner.py
bin/ratlib/safe_archive.py
bin/ratlib/run_manifest.py
schemas/rat.run.v1.json
tests/test_stability.py
```

JSON mode는 P1 envelope가 구현되기 전까지 versioned provisional 형식임을 표시한다. P1 병합 시
`rat.tool-result/v1`로 한 번만 전환한다.

## 6. 하위 호환성 및 migration

- 옵션 없는 `recon`, `revq`, `decomp`, `pkselftest` 텍스트 출력과 정상 종료 code 0을 유지한다.
- 유효한 기존 `rat.run/v1`은 사용자 필드와 lifecycle 상태를 보존해 병합한다. schema 이전의 legacy manifest는
  자동 추측·변환하지 않고 validation 오류로 중단한다.
- 기존 `<binary>.decomp/`는 key 정보가 없으므로 read-only legacy cache로 인식한다. 첫 명시적 refresh에서 새
  cache로 만들고, 자동 삭제하지 않는다.
- 기존 archive extraction destination의 기존 entry는 덮어쓰지 않는다. 충돌이 없는 새 top-level entry만 공개한다.
- exit code가 항상 0이던 legacy selftest 호출자는 release note에서 변경을 고지한다.

## 7. 실패 모드와 보안 조건

| 실패 모드 | 요구 동작 |
|---|---|
| zip-slip/tar traversal | member 단위 거부가 아니라 archive 전체 실패, destination 불변 |
| symlink/hardlink/device | archive 전체 실패, 링크 target을 열지 않음 |
| zip bomb/너무 많은 member | streaming 중 즉시 중단, code 4, 한도와 관측값 기록 |
| weird filename | argv 배열로만 처리, 안전하게 표시, 충돌이면 거부 |
| timeout/forked child | process group 종료, code 124, partial/truncation 기록 |
| stale decomp cache | miss 후 재분석; legacy/stale 결과를 fact로 승격하지 않음 |
| missing dependency | code 3; optional이면 명시적 skip/partial |
| partial analysis | 확보한 checkpoint/count와 누락 사유를 `partial` 또는 `timeout`으로 기록 |
| manifest write 중 crash | 이전 valid manifest 유지, temp 파일은 다음 시작 때 격리 |
| target 불일치 | `ctfguard` code 5, subprocess 시작 전 거부 |

secret은 argv, manifest, stderr, artifact logical name에 넣지 않는다. archive 안의 binary에는 실행 bit가 있어도
자동 실행하지 않는다.

## 8. 테스트 fixture와 실행 명령

필수 fixture:

- malicious archive: `../`, absolute, symlink/hardlink, device, duplicate, zip bomb, nested depth 초과.
- weird filename: 공백, newline, leading dash, glob 문자, 비ASCII, 아주 긴 이름, NFC/NFD 구분.
- timeout: sleep, CPU loop, fork child, stdout flood, TERM 무시.
- stale cache: 같은 basename/mtime의 다른 binary, Ghidra/script version 변경, 중간 종료 cache.
- missing dependency: Ghidra, angr, Qiling, rootfs 각각 부재.
- partial analysis: 일부 함수 decompile 실패, CFG timeout, trace hard cap.

구현 후 실행 명령:

```sh
python3 -m unittest tests.test_stability
python3 bin/ctfpull selftest
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
bin/pkselftest --strict-optional
python3 tests/e2e_mock.py
bash tests/e2e_rev.sh
```

dependency가 없는 CI job은 skip 이유를 assertion하고, dependency-full job에서 전체 GREEN을 별도로 요구한다.

## 9. 완료 기준

- [x] 도구 전용 file scope와 공유 `.gitignore` 정리가 [검증 기록](P0_VERIFICATION.md)에 분리돼 있다.
- [x] B001~B007 각각 unit fixture와 최소 1개 e2e 경로가 있다.
- [x] malicious archive가 destination 밖에 byte/link/device를 만들지 못한다.
- [x] timeout/cancel 뒤 descendant process가 남지 않고 exit/status가 표와 일치한다.
- [x] 필수 selftest failure가 CI를 실제로 실패시킨다.
- [x] manifest는 atomic하고 input/tool provenance를 재현 가능하게 기록한다.
- [x] stale/partial decomp cache와 fallback이 정상 cache hit로 표시되지 않는다.
- [x] revq schema fixture에서 block/instruction 값과 label이 ground truth와 일치한다.
- [x] Qiling missing/instruction-budget/wall-timeout case가 hang 없이 종료되고 background 실행이 남지 않는다.
- [x] `ctfguard`, primitive gate, Docker/libc provenance, decomp fallback의 검증 순서를 모두 통과한다.
- [x] 기존 텍스트 CLI smoke test와 문서 예제가 통과한다.

## 10. 권장 커밋 분할

커밋은 사람의 명시 요청이 있을 때 다음 순서로 작게 나눈다.

1. `chore: checkpoint tool-only changes and ignore runtime artifacts`
2. `test: lock guard primitive and libc provenance behavior`
3. `fix: harden archive extraction and subprocess limits`
4. `fix: propagate selftest failures and timeout status`
5. `feat: validate and atomically write run manifest`
6. `fix: key decomp cache by content and expose fallback status`
7. `fix: separate revq block/instruction counts and stop qiling runs`
8. `docs: align setup doctrine and CLI failure semantics`

검증 순서는 (1) `ctfguard` active/target fail-closed, (2) primitive gate의 hypothesis→PASS 거부/승격,
(3) Docker/libc hash·loopback provenance, (4) decomp exact/alias/fallback, (5) 전체 selftest다.

## 11. 진행 체크리스트

- [x] P0.0 checkpoint/ignore
- [x] B001 safe archive
- [x] B002 subprocess runner
- [x] B003 selftest exit
- [x] B004 manifest
- [x] B005 decomp cache
- [x] B006 revq instruction/block count
- [x] B007 Qiling hook/stop
- [x] code/documentation parity review
- [x] [완료 기준](#9-완료-기준) 전체 확인
