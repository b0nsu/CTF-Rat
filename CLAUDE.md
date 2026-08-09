# ctf-rat — CTF(pwn/rev) 풀이 kit (Claude Code / Codex 진입점)

> 이 파일은 세션이 레포 루트에서 열리면 자동 로드된다. **너는 이 kit 으로 CTF 문제를 푼다.**
> 환경 세팅은 [SETUP.md](SETUP.md) 한 번. 이후 클론한 그 자리에서 바로 돈다(WSL SSH·원격배포 없음).

## 🚩 START HERE
- **정체**: pwn/rev 집중형 **self-contained CTF 풀이 kit.** 도구(`bin/`) + doctrine(`doctrine/`) +
  지식(`knowledge/`) + 참조데이터(`reference/`) 가 한 레포에. 어느 Linux 환경이든 [SETUP.md](SETUP.md) 로 준비.
- **읽는 순서**: 이 절 → [doctrine/SOLVING.md](doctrine/SOLVING.md)(**ROE + 6-phase 프로토콜, 최우선**) →
  [doctrine/SOLVABILITY.md](doctrine/SOLVABILITY.md)(확실히 풀 수 있나 게이트) →
  [doctrine/PRIMITIVE_GATE.md](doctrine/PRIMITIVE_GATE.md)(**hypothesis→primitive SELF 확인 게이트**) →
  [knowledge/GROUNDING_INDEX.md](knowledge/GROUNDING_INDEX.md)(유형→지식 라우터).
  결승/팀전은 [doctrine/FINALS.md](doctrine/FINALS.md). 커널은 [kernel/CLAUDE.md](kernel/CLAUDE.md).
- **환경 미준비면**: 먼저 [SETUP.md](SETUP.md)(venv+angr+pwntools, Ghidra, glibc-fetch) → selftest 4종 GREEN 확인.

## ⛔ 규칙 (위반 금지)
- **교전 범위(ROE)**: 오직 **이번 챌린지의 지정 타겟만**(주어진 바이너리 · 지정 nc host:port · 지정 ssh 계정).
  타 호스트·타 팀 인스턴스·대회 인프라 스캔/접속 **절대 금지**. 상세 = doctrine/SOLVING.md 최상단.
- **honest-mode**: flag 자동제출 금지(ToS — 제출은 사람). **진짜 검증 없이 "풀렸다" 보고 금지.** 오프셋/주소는 live 실측.
- **한 번에 활성 문제 1개.** 팬아웃은 문제 "안"에서만(vuln class 좁히기·verify 확신 올리기). 문제-간 자동배분 안 함.
- **활성 문제 락 강제**: CTF 작업 시작 전 반드시 `ctfguard begin <chal> [target...]` 로 단일 active lock 을 잡는다.
  `state init`/`newchal` 은 active challenge 와 이름이 다르면 실패해야 정상이다. 다른 문제로 전환하려면 먼저
  `ctfguard finish blocked|complete` 로 현재 문제를 명시 종료하고 사람에게 보고한다. `nc`/`ssh` 접속은
  `ctfguard nc <host> <port>` / `ctfguard ssh <user> <host> <port>` 또는 `ctfguard check-target ...` 통과 후에만 한다.
- **git push 는 사람만.** 커밋/푸시는 명시 요청 시에만.
- **CTF-RAT strict gate**: fact / hypothesis / primitive PASS 를 분리한다. 미검증 가설은 `state hypothesis ...` 로만 기록하고,
  최소 payload로 일반 실행 core 또는 remote-equivalent 실행에서 EIP/ESP/register/controlled marker/terminator 부작용을 확인하기 전까지
  ROP·shellcode·remote exploit chaining 금지. 통과 시에만 `state primitive <name> pass <evidence>` 로 승격한다.

## 풀이 워크플로 (6-phase 요약; 상세=doctrine/SOLVING.md)
0. **Guard** — `ctfguard begin <name> [user@host:port|host:port]` 로 active lock + target allowlist 를 먼저 만든다.
   시작 전 `ctfguard check` 가 GREEN 이어야 한다. 새 문제 전환은 `ctfguard finish blocked|complete` 없이는 금지.
1. **Triage** — `ctfpull ctfd --id N`(수집) → `newchal <name> <bin> [libc] [host:port]`(스캐폴드).
   pwn 이면 `recon <bin>`, rev 이면 `revq <bin>`. `doctrine/SOLVABILITY.md` 로 확신도 게이트.
2. **RE/정찰** — 큰 정적 읽기는 **scout Task 로 위임하고 요약만 회수**(컨텍스트 위생). rev: `revq --func`/`decomp`.
3. **Vuln 가설** — 불확실하면 가설별 병렬(상한 3). `knowledge/GROUNDING_INDEX.md` 로 유형별 지식 1개만 로드.
4. **Primitive** — leak/AAW/control 확보(순차). 후보는 `state hypothesis ...`; SELF 확인 통과 후 `state primitive <name> pass <evidence>`.
5. **Exploit 체이닝** — primitive PASS 이후에만 한 컨텍스트에 조립. hypothesis만으로 체이닝 금지.
6. **Adversarial verify** — SOLVE 선언 전 skeptic 으로 **반증 시도**(leak 위양성·libc mismatch·local↔remote 차).
   rev 는 `symsolve --find-str …`(복원 입력을 **실 바이너리 재실행**으로 concrete-verify)로 executable oracle 검증.
7. **Writeup**(선택, SOLVE 후) — `knowledge/ctf-writeup/SKILL.md` 표준형식(메타 + Summary + 1~3 step + 완결 스크립트 + Flag).
   rev grounding 은 `knowledge/ctf-reverse/`, pwn 은 `knowledge/ctf-skills/` — 라우팅은 `knowledge/GROUNDING_INDEX.md`.

## 도구 (bin/) — 전부 `CTF_HOME`(레포루트) 자동 해석
```
GUARD    ctfguard          active 문제 락 + target allowlist + nc/ssh 래퍼(위반 시 fail-closed)
INGEST   ctfpull            CTFd 문제 수집 → newchal (flag 자동제출 X)
스캐폴드  newchal            solve 디렉토리 스캐폴딩 (+run.json)
triage   recon              pwn 정적 프로파일 + 보수적 triage
         revq               rev 정적 배치 — 함수/문자열/xref/interesting/evasion (angr 주 엔진)
         analyze            그래프+1-hop 전파 vuln localizer (prior only)
RE       decomp             Ghidra headless 디컴파일 캐시(함수별 조회)
         gdbq               GDB batch (노이즈 제거)
symbolic solve/_template/rev/symsolve.py   angr 하니스(+concrete-verify, PE면 wine)
         solve/_template/rev/vmlift.py     custom-VM 리프터 스캐폴드
         solve/_template/rev/qiling_trace.py  Windows PE 동적 에뮬(Qiling, Wine 불필요)
pwn      pwnkit / pwnstage / primitives.template.py   프리미티브·익스 조립
버스     state              STATE.jsonl (확정/배제/다음 기록 — 재도출 방지)
검증     pkflag(포맷) pkselftest  |  공유 pkshare/pkstart  |  팀 teamreg/teamsync/teamstate
kernel   k_run_qemu k_repack k_dump_heap k_kallsyms (kernel/CLAUDE.md 참조)
```
rev 시너지: `revq` 주소 = angr 로드베이스(PIE 0x400000) → `symsolve --find <그 주소>` 그대로 투입.

## 레이아웃
```
CLAUDE.md / AGENTS.md      이 진입점 (AGENTS.md→CLAUDE.md 심볼릭, Codex 호환)
SETUP.md                   환경무관 초기 세팅
doctrine/                  SOLVING(ROE+6-phase) · SOLVABILITY · calibration · FINALS
knowledge/                 GROUNDING_INDEX + ctf-skills/(pwn) + ctf-reverse/(rev) + ctf-writeup/
reference/                 libc-offsets/ · glibc/(list·SOURCES·glibc-fetch)
bin/                       도구 전체 (+ghidra_scripts/)
solve/_template/rev/       symsolve · vmlift (챌린지 dir 로 복사해 사용)
kernel/                    커널 pwn 확장(CLAUDE.md·.gdbinit-kernel)
tests/                     e2e_mock.py(ctfpull) · e2e_rev.sh(rev 루프)
```

## 테스트 (도구 수정 후 회귀검증 — 전부 ALL GREEN)
```sh
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 bin/ctfpull selftest && python3 tests/e2e_mock.py
```
angr 설치 환경이면 `bash tests/e2e_rev.sh`(실 crackme e2e)까지.
