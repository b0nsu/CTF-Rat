# ctf-rat — CTF(pwn/rev) 풀이 kit

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/64cf751b-64c8-4666-8b34-9a83ec0710c5" />

pwn/rev 집중형 **환경 무관 self-contained CTF 풀이 kit.** 도구 + doctrine + 지식 + 참조데이터가
한 레포에 들어 있어, 어느 Linux 환경(네이티브/VM/WSL2/컨테이너)에든 한 번 세팅하면
Claude·Codex 가 이 레포에서 바로 문제를 푼다.

- **세팅**: [SETUP.md](SETUP.md) (venv+angr+pwntools, Ghidra, glibc-fetch — 한 번)
- **에이전트 진입점**: [CLAUDE.md](CLAUDE.md) (= `AGENTS.md`, Codex 호환). 기본은 **FAST path**: artifact → `rat route` → bounded query → concrete verify. 6-phase/doctrine은 필요할 때만 DEEP으로 lazy-load한다.
- **FAST path 설계**: [docs/CODEX_FAST_PATH.md](docs/CODEX_FAST_PATH.md). 진입 시 필수 독서가 아니라 아키텍처 참고문서다.
- **strict DEEP 참고**: [doctrine/SOLVING.md](doctrine/SOLVING.md) · [doctrine/SOLVABILITY.md](doctrine/SOLVABILITY.md) · [doctrine/PRIMITIVE_GATE.md](doctrine/PRIMITIVE_GATE.md). FAST가 막히거나 primitive/environment 검증이 필요할 때만 읽는다.
- **지식**: [knowledge/GROUNDING_INDEX.md](knowledge/GROUNDING_INDEX.md)에서 현재 문제에 필요한 파일 **하나만** 고른다. 전체 knowledge tree를 startup에서 읽지 않는다.
- **측정**: [docs/MEASUREMENT.md](docs/MEASUREMENT.md) + `rat-metrics`. full benchmark corpus/ablation manifests는 `dev`에서 관리하고, 운영 브랜치에는 최소 계측 도구만 둔다.
- **도구 커버리지/추가 우선순위**: [doctrine/TOOLING_GAP_ANALYSIS.md](doctrine/TOOLING_GAP_ANALYSIS.md) — 기존 `bin/` 계층, 통합 갭, 신규 도구 gate.

## 기본 Codex 루프

```sh
ctfguard begin <challenge>       # 새 문제일 때 1회
rat route ./chall                # cheap deterministic routing
revq ./chall --interesting       # rev 후보 좁히기
rat-func-v2 ./chall <candidate>  # structured bounded function card
rat-oracle ./chall --command     # lexical output oracle -> cache-aware symsolve command
# 또는 pwn이면 recon ./chall
rat snapshot --root . --budget-bytes 6000   # 누적 state 재주입 대신 projection
```

정상 hot path는 **route → query → test → verify**다. 시작부터 doctrine 전체, full decompile, state history, tool catalog를 컨텍스트에 올리지 않는다. 신호 충돌·난독화/동적 전용·primitive 증명·remote 환경 동등성처럼 실제 이유가 있을 때만 기존 P0-P5 orchestration으로 승격한다.

## 레이아웃

```text
CLAUDE.md / AGENTS.md      bounded FAST-path 에이전트 진입점 (심볼릭)
SETUP.md                   환경무관 초기 세팅
docs/CODEX_FAST_PATH.md    FAST→DEEP 정책과 아키텍처
docs/MEASUREMENT.md        ablation/telemetry 사용법
doctrine/                  DEEP용 SOLVING · SOLVABILITY · PRIMITIVE_GATE · calibration
knowledge/                 vendored pwn/rev 지식 + repo-owned learned/ + writeup 절차
reference/                 libc-offsets/ · glibc/(list·SOURCES·glibc-fetch)
bin/                       도구 전체 (+ghidra_scripts/)
solve/_template/rev/       symsolve · vmlift
kernel/                    커널 pwn 확장
tests/                     unit/e2e regression tests
```

## 핵심 도구

- **`rat route <artifact>`** — cheap deterministic first routing. file/import/string 신호와 현재 cache 상태, bounded NEXT를 반환한다.
- **`rat-func-v2 <bin> <func|addr>`** — 기존 `revq --json` 사실을 structured cache로 재사용해 caller/callee, compare/input calls, role/oracle 신호와 coverage를 제한된 카드로 반환한다. 없는 branch/value-flow 사실은 채워 넣지 않는다.
- **`rat-oracle <bin> --command ...`** — unambiguous success/failure 문자열을 symbolic output oracle로 연결한다. `revq`의 string-xref 주소는 **evidence locator**로만 보존하고 자동 `--find/--avoid` 주소로 승격하지 않는다. 생성 명령은 lexical `--find-str/--avoid-str`를 우선해 concrete re-run 검증 경로를 유지한다.
- **`rat-bslice <bin> <func> <anchor>`** — **실험 A5** bounded VEX slice. anchor block의 in-function predecessor guard에서 tmp/same-block register def-use와 direct stack slot만 추적하고 `taken`/`must-not-take` 관계를 표시한다. inter-block value-flow/alias proof는 하지 않는다.
- **`rat snapshot`** — append-only STATE 전체 대신 모델에 필요한 projection만 제한된 크기로 반환한다.
- **`rat-adapt --root . --emit stdout ...`** — `revq/recon/gdbq/symsolve/decomp`의 성공·비절단 deterministic query를 canonical structured cache/artifact store로 재사용한다. legacy sidecar는 마이그레이션 동안 유지한다.
- **`rat-metrics`** — benchmark 때만 켜는 opt-in telemetry. verified solve/time-to-flag/context/tool duplicates/structured-cache/model usage를 집계한다.
- **`ctfpull`** — CTFd 문제 수집 → `newchal` 스캐폴드. flag 자동제출 안 함(ToS+honest-mode).
  ```sh
  ctfpull ctfd --list [--category pwn]
  ctfpull ctfd --id 42 [--dest DIR]
  ```
- **`recon <bin>`** — pwn 정적 프로파일 + 보수적 triage.
- **`rat-doctor <bin> --format json`** — native/GDB/angr/Ghidra/QEMU/Qiling/Wine 실행 가능성과 차단 원인을 확인한다. FAST 기본 호출은 아니며 환경 문제가 실제로 생겼을 때 사용한다.
- **`rat-scenario init|validate|show`** — `rat-dyn`/`rat-runtime`/`rat-verify`가 공유하는 입력·argv·env·oracle 정규화.
- **rev 루프** — `revq` → `rat-func-v2` → 필요할 때만 `decomp` → `rat-oracle`/`symsolve.py` + concrete verify → custom VM이면 `vmlift.py`.
  ```sh
  revq <bin> --interesting
  rat-func-v2 <bin> <name>
  decomp <bin> <name>
  rat-oracle <bin> --command --stdin 16 --printable
  symsolve.py <bin> --find-str Correct --avoid-str Wrong --stdin 16 --printable
  vmlift.py --disasm|--run|--solve [blob]
  ```
  주소 기반 symbolic target은 **CFG block-entry로 검증된 경우에만** 사용한다. 일반 string-xref 명령어 주소를 그대로 `--find/--avoid`로 넣지 않는다.
- **pwn**: `pwnkit`/`pwnstage`/`primitives` · `pwncalc`/`pwnleak`/`pwnpayload`/`pwnropcheck`/`pwncrash`/`pwnscope`.
- **state/evidence**: `state`. fact/hypothesis/primitive를 구분하며 hypothesis만으로 exploit chain을 확정하지 않는다.
- **인계·지식화**: `pkshare` → `HANDOFF.md`, `writeupcheck` 품질 검사 → 검토된 교훈은 `knowledge/learned/`.

## 테스트

```sh
python3 bin/rat selftest
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 bin/ctfpull selftest && python3 tests/e2e_mock.py
python3 -m unittest discover -s tests -p 'test_*.py'
bash tests/e2e_rev.sh
```

의존성이 있는 e2e는 환경에 따라 skip될 수 있다. FAST/telemetry/cache/function-card/oracle/bounded-slice 변경은 unit discovery와 operational regression을 통과해야 한다.

## 운영 원칙

한 번에 활성 문제 1개. FAST에서는 main agent + bounded deterministic query가 기본이며 **fan-out하지 않는다**. 큰 원시 읽기가 bounded query로 줄어들지 않을 때만 scout를 사용하고, raw dump 대신 결론과 evidence locator만 회수한다. 동일 입력의 결정적 도구를 반복 호출하기 전에 cache/state를 확인한다. 속도 최적화는 검증 경계에서 멈춘다: 실제 실행·oracle·환경 증거 없이 SOLVED를 주장하지 않는다.
