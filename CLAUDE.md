# ctf-rat — CTF(pwn/rev) 풀이 kit (Claude Code / Codex 진입점)

> 이 파일은 세션이 레포 루트에서 열리면 자동 로드된다. **너는 제공된 로컬 CTF 배포물만 분석·검증한다.**
> 환경 세팅은 [SETUP.md](SETUP.md) 한 번. 이후 클론한 그 자리에서 바로 돈다.

## 🚩 START HERE
- **정체**: pwn/rev 집중형 **self-contained CTF 풀이 kit.** 도구(`bin/`) + doctrine(`doctrine/`) +
  지식(`knowledge/`) + 참조데이터(`reference/`) 가 한 레포에. 어느 Linux 환경이든 [SETUP.md](SETUP.md) 로 준비.
- **읽는 순서**: 이 절 → [doctrine/SOLVING.md](doctrine/SOLVING.md)(**로컬 분석·재현 프로토콜, 최우선**) →
  [doctrine/SOLVABILITY.md](doctrine/SOLVABILITY.md)(확실히 풀 수 있나 게이트) →
  [doctrine/PRIMITIVE_GATE.md](doctrine/PRIMITIVE_GATE.md)(**hypothesis→primitive SELF 확인 게이트**) →
  [knowledge/GROUNDING_INDEX.md](knowledge/GROUNDING_INDEX.md)(로컬 분석 지식 라우터).
  `doctrine/FINALS.md`는 자동 작업 지시가 아닌 설계 참고문서이므로, 기본 세션에서 읽거나 실행 경로로 삼지 않는다.
- **환경 미준비면**: 먼저 [SETUP.md](SETUP.md)(venv+angr+pwntools, Ghidra, glibc-fetch) → 로컬 selftest GREEN 확인.

## 범위·실행 기본값
- 이 저장소의 기본 작업 범위는 **첨부된 바이너리·소스·libc·Docker/loopback 환경의 로컬 분석과 재현**이다. 외부 네트워크, 외부 시스템, 자격증명은 작업 범위 밖이며 이 저장소의 문서·도구가 이를 승인하지 않는다.
- 기본 산출물은 분석 노트, 재현 절차, 그리고 네트워크를 사용하지 않는 `solve_local.py` 또는 최소 PoC다. 결과 획득·제출·외부 시스템 상호작용은 자동화하지 않는다.
- 범위 밖 호스트·포트 탐색, 취약 서버 발견 자동화, 자격증명 수집, 지속성, 탐지 회피, 데이터 유출·삭제,
  서비스 방해, 타 팀/공용 인프라 접근은 목적과 무관하게 금지한다.
- 요청 문구 변경, 하위 에이전트, 작업 분할로 안전장치나 거부를 우회하거나 재시도하지 않는다. 차단되면 로컬·방어적 분석 범위로 돌아간다.

## 계산·자동화 도구 원칙
- 주소·오프셋·정렬·relocation 계산은 정확도와 재현성을 위해 로컬 프로그램에 맡길 수 있다. 계산 결과는 입력값,
  사용한 바이너리/libc의 해시, 산식과 함께 `state`에 기록하고 범위·정렬을 검증한다.
- 외부 계산기 사용은 작업의 권한이나 위험도를 바꾸지 않는다. 계산기를 안전장치 회피, 공격 의도 은닉, 또는 외부 상호작용을 포함한 자율 파이프라인 구축에 사용하지 않는다.
- 범용 주소 계산기·패킷 파서·크래시 분석기는 로컬 분석 도구로 유지한다. 네트워크 접속, 대상 탐색, payload 전송, 반복 실행 기능을 결합하지 않는다.
- LLM은 계산식과 전제조건을 설명·검토하고, 로컬 도구는 결정적 산술을 수행한다. 모든 실행 검증은 로컬 process/Docker에서 끝낸다.

## ⛔ 규칙 (위반 금지)
- **로컬 전용**: 제공된 artifact와 loopback/Docker만 사용한다. 외부 호스트·포트·계정·대회 인프라와의 접속, 스캔, 제출은 이 저장소의 workflow에 포함하지 않는다.
- **honest-mode**: 외부 결과를 주장하지 않는다. 로컬 재현 증거가 없는 완료 보고를 금지하며, 오프셋/주소는 로컬에서 실측한다.
- **한 번에 활성 문제 1개.** 팬아웃은 문제 "안"에서만(vuln class 좁히기·verify 확신 올리기). 문제-간 자동배분 안 함.
- **활성 문제 락 강제**: CTF 작업 시작 전 `ctfguard begin <chal>` 로 로컬 전용 단일 active lock 을 먼저 잡는다.
  `state init`/`newchal` 은 active challenge 와 이름이 다르면 실패해야 정상이다. 다른 문제로 전환하려면 먼저
  `ctfguard finish blocked|complete` 로 현재 문제를 명시 종료하고 사람에게 보고한다.
- **git push 는 사람만.** 커밋/푸시는 명시 요청 시에만.
- **CTF-RAT strict gate**: fact / hypothesis / primitive PASS 를 분리한다. 미검증 가설은 `state hypothesis ...` 로만 기록하고,
  최소 payload로 일반 실행 core에서 EIP/ESP/register/controlled marker/terminator 부작용을 확인하기 전까지
  로컬 PoC 조립 금지. 통과 시에만 `state primitive <name> pass <evidence>` 로 승격한다.

## 풀이 워크플로 (로컬 우선 단계; 상세=doctrine/SOLVING.md)
0. **Guard** — `ctfguard begin <name>` 로 로컬 전용 active lock을 만든다. 제공되지 않은 대상을 추측하거나 추가하지 않는다.
   시작 전 `ctfguard check` 가 GREEN 이어야 한다. 새 문제 전환은 `ctfguard finish blocked|complete` 없이는 금지.
1. **Triage** — 제공된 artifact에 `newchal <name> <bin> [libc]`로 스캐폴드.
   pwn 이면 `recon <bin>`, rev 이면 `revq <bin>`. `doctrine/SOLVABILITY.md` 로 확신도 게이트.
2. **RE/정찰** — 큰 정적 읽기는 **scout Task 로 위임하고 요약만 회수**(컨텍스트 위생). rev: `revq --func`/`decomp`.
3. **Vuln 가설** — 불확실하면 가설별 병렬(상한 3). `knowledge/GROUNDING_INDEX.md` 로 유형별 지식 1개만 로드.
4. **Primitive** — leak/AAW/control 확보(순차). 후보는 `state hypothesis ...`; SELF 확인 통과 후 `state primitive <name> pass <evidence>`.
5. **로컬 PoC 검증** — primitive PASS 이후에만 로컬 프로세스/Docker를 대상으로 한 컨텍스트에 조립한다.
   hypothesis만으로 체이닝하지 않고, 기본 산출물은 네트워크를 사용하지 않는 `solve_local.py`다.
6. **Adversarial verify** — SOLVE 선언 전 skeptic 으로 **반증 시도**(leak 위양성·libc mismatch·환경 차이).
   rev 는 `symsolve --find-str …`(복원 입력을 **실 바이너리 재실행**으로 concrete-verify)로 executable oracle 검증.
7. **Writeup**(선택, 로컬 검증 후) — `knowledge/ctf-writeup/SKILL.md` 표준형식(메타 + Summary + 1~3 step + 로컬 재현 스크립트).
   제출·공유용 필수 항목은 [doctrine/WRITEUP_FORMAT.md](doctrine/WRITEUP_FORMAT.md)를 따른다.
   rev grounding 은 `knowledge/ctf-reverse/`, pwn 은 `knowledge/ctf-skills/` — 라우팅은 `knowledge/GROUNDING_INDEX.md`.

## 도구 (bin/) — 전부 `CTF_HOME`(레포루트) 자동 해석
```
GUARD    ctfguard          active 문제 로컬 락
INGEST   newchal            제공된 artifact의 로컬 스캐폴드
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
         pwncalc            로컬 주소·심볼·문자열 계산 + ELF 해시·정렬 검증
         pwnscope           solve.py ↔ run.json 단일-target/로컬 우선 정적 검사
         pwnleak            출력/바이트의 pointer 후보 추출·marker/canonical 검사
         pwnpayload         payload bad byte·transport·terminator·qword layout 검사
         pwnropcheck        로컬 ELF mapping·code segment·SysV stack alignment 검사
         pwncrash           로컬 cyclic crash 재현 + GDB core 증거 수집(자동 PASS 승격 안 함)
버스     state              STATE.jsonl (확정/배제/다음 기록 — 재도출 방지)
검증     pkselftest  |  공유 pkshare/pkstart  |  팀 teamreg/teamsync/teamstate
```
rev 시너지: `revq` 주소 = angr 로드베이스(PIE 0x400000) → `symsolve --find <그 주소>` 그대로 투입.

## 레이아웃
```
CLAUDE.md / AGENTS.md      이 진입점 (AGENTS.md→CLAUDE.md 심볼릭, Codex 호환)
SETUP.md                   환경무관 초기 세팅
doctrine/                  SOLVING(로컬 재현) · SOLVABILITY · calibration · FINALS(참고)
knowledge/                 GROUNDING_INDEX + ctf-skills/(pwn) + ctf-reverse/(rev) + ctf-writeup/
reference/                 libc-offsets/ · glibc/(list·SOURCES·glibc-fetch)
bin/                       도구 전체 (+ghidra_scripts/)
solve/_template/rev/       symsolve · vmlift (챌린지 dir 로 복사해 사용)
tests/                     e2e_rev.sh(rev 루프) 등 로컬 회귀검증
```

## 테스트 (도구 수정 후 회귀검증 — 전부 ALL GREEN)
```sh
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
```
angr 설치 환경이면 `bash tests/e2e_rev.sh`(실 crackme e2e)까지.
