# ⛔ 교전 범위 (RULES OF ENGAGEMENT) — 최우선, 위반 절대금지
- **오직 이번 챌린지의 지정된 타겟만** 공격/접속: 명시적으로 주어진 바이너리 · 지정된 nc host:port · 지정된 ssh 계정. 그 외 어떠한 것도 건드리지 말 것.
- **타 팀 인스턴스 · 타 호스트 · 대회 인프라 공격/스캔/접속 절대 금지.** 포트스캔·네트워크 정찰·lateral movement·공유인프라 접근 금지. 익스플의 연결/스캔 대상은 반드시 오케스트레이터가 준 단일 타겟으로 국한.
- 타겟이 in-scope인지 불확실하면 **멈추고 물어볼 것.** (대회 실격/규정위반·무관한 제3자 피해 방지)

> **결승 당일: doctrine/FINALS.md 배틀플랜을 먼저 읽고 따를 것.**

# CTF pwn 작업 규칙 (이 디렉토리에서 Claude Code 구동)

> **판정 기준은 SOLVABILITY.md 참조 — 확신(SOLVE)은 바이너리에서 fresh 도출+실증했을 때만. 답/writeup 검색 금지.**

## 미션
userland x86-64 linux pwn (heap 비중 큼). 목표: 빠르게 풀 수 있는 것 거르고, context 안 터뜨리며, 실제 바이너리로 검증하며 flag 획득.

## 고정 루프 (rabbit-hole 방지 — 순서 지킬 것)
1. `newchal <name> <bin> [libc] [host:port]` → solve 디렉토리 + recon + state.md 자동
2. **triage 판정** 보고 tier 결정 (🟢 먼저, 🟠/🔴 후순위)
3. `decomp <bin> <func>` 로 vuln 함수 **하나씩** 확인 → vuln class 확정 → **`knowledge/GROUNDING_INDEX.md` 라우터로 해당 class 지식파일 특정**(통째 로드 금지·subagent로 해당 절만).
4. primitive 확보 → leak → 최종 exploit
5. **매 단계 exploit.py 로 실제 바이너리에 실행**해 검증 (추론만 금지)

## context 규율 (터지지 않게)
- **decomp/gdbq만 사용**. `objdump -d` 전체, raw `gdb`, ghidra 전체 덤프 금지.
- `decomp <bin>` = 함수 목록, `decomp <bin> <func>` = 함수 하나. 절대 전체를 붙이지 말 것.
- 함수 RE·strings 대량 스캔 등 **큰 읽기는 subagent(Task)에 위임** → 결론만 회수.
- 주소/offset/gadget은 매번 **state.md 에 기록 후** 사용 (hallucinate 방지).

## triage rubric
- 🟢 FAST: no PIE+win+overflow(ret2win) / 직접 fmt / overflow+system+/bin/sh
- 🟡 STANDARD: leak 필요 ROP, ret2libc+one_gadget, heap(glibc≤2.31 hooks), seccomp+ORW
- 🟠 HARD: heap glibc≥2.34(FSOP/House of *), custom VM, 다단계+다제약
- 🔴 SKIP: 커널/브라우저, 심한 난독화 대형, 정보부족

## 도구
| 목적 | 명령 |
|---|---|
| 정찰+triage | `recon <bin> [libc]` |
| 디컴파일(on-demand) | `decomp <bin> [func]` |
| 동적분석(배너 off) | `gdbq <bin> "b *main" "run" "heap bins"` |
| 스캐폴딩 | `newchal <name> <bin> [libc] [host:port]` |
| libc 매칭/오프셋 | `glibc-aio identify ./libc.so.6` / `glibc-aio search --symbol printf=0x...` |
| one_gadget | `one_gadget ./libc.so.6` (캐시: reference/libc-offsets/) |
| gadget | `ROPgadget --binary <bin> | grep 'pop rdi'` |
| seccomp | `seccomp-tools dump ./chall` |
| exploit | `./exploit.py` (`GDB`/`REMOTE` args) |

## 지식 계층 (grounding — driver 아님)
- heap 기법: `~/gnnPwn/data/rag_corpus/how2heap/` (glibc 버전별). triage가 heap일 때만 참조.
- 기법 카탈로그: `knowledge/ctf-skills/` (vendored). **라우터=`knowledge/GROUNDING_INDEX.md`** — class→파일 매핑·사용규율. driver 아님(SKILL의 tool-setup/gdb quickstart 무시, 우리 gdbq/pwnkit/state가 상위).
- **원칙**: 지식은 grounding, 실제 solving은 이 바이너리 위 추론, 웹검색은 N회 막힐 때만 좁게.
- glibc 버전별 게이팅: safe-linking 2.32+, hooks 제거 2.34+, tcache 2.26+. how2heap 버전 태그 우선.

## venv
python/pwntools는 `./venv/bin/python`. exploit.py 는 이미 그 shebang. 새 스크립트도 동일하게.

## glibc-aio 주의 (CWD-relative)
- glibc-aio 의 `list`/`libs/` 는 **실행 CWD 기준**. staged libc는 `reference/glibc/` 에 있음.
- download/search/버전조회는 `cd reference/glibc` 후 실행: `glibc-aio 2.35 system`, `glibc-aio search 2.35`.
- 챌린지 libc 식별은 절대경로로: `glibc-aio identify /abs/path/libc.so.6` (BuildID 온라인).
- one_gadget 오프셋 캐시: `reference/libc-offsets/<version>.txt`.
- **로그인 CWD가 /mnt/c(윈도우FS)** 라 작업은 반드시 `cd 레포 루트` 에서.

## heap/동적 디버깅 (중요 — gdbq 한계 정정)
- **gdbq 는 -batch + stdin 주입 없음** → 메뉴 기반/heap 챌린지엔 부적합(BP 도달 못 함). 정적·단순 관찰(함수 디스어셈, 심볼)용으로만.
- heap·인터랙티브 디버깅 **주력 = exploit.py 안에서 `gdb.attach`/`gdb.debug`** (pwntools 가 입력 드라이브 + pwndbg 관찰):
  ```python
  GS = 'b *add+0x40\ncommands\n heap bins\n end\ncontinue\n'
  io = gdb.debug([exe.path], gdbscript=GS)   # 또는 ./exploit.py GDB
  # 메뉴 진행하며 malloc/free 후 heap bins / vis 확인
  ```
- glibc 게이팅(정확): tcache 2.26+, safe-linking 2.32+, __free_hook/__malloc_hook 제거 2.34+. <2.32 이면 hook overwrite 가 가장 쉬움.

## batch triage
- 대회 시작 시 여러 챌린지 한 번에 거르기: `triage-all <디렉토리|bin...>` → tier 정렬표. 🟢/🟡 먼저.

## 다중 에이전트 phase 프로토콜 (언제 팬아웃/수렴 — 한 문제 집중형)
> 전략: 한 번에 활성 문제 1개. 팬아웃은 문제 "안"에서만(vuln class 좁히기·verify 확신 올리기). 문제-간 자동배분(lease/queue/worker) 안 만듦. 상세·근거=러너 개발 워크스페이스 `ctf-runner/RUNNER_ARCHITECTURE.md`(Mac dev).

문제 하나를 6 phase로 보고, phase마다 팬아웃 on/off를 고정한다:
| Phase | 주체 | 팬아웃 | 규칙 |
|---|---|---|---|
| P0 Triage | 오케스트레이터 단독 | ❌ | `recon`+triage rubric. 전역 시야 필요 — 여기서 팬아웃=조율비용 낭비 |
| P1 RE/정찰 | scout Task ×N | ⚠️위임(≠팬아웃) | 큰 읽기(대형 `decomp`/strings/xref)는 **항상** Task로, 결론만 STATE 회수 |
| P2 Vuln 가설 | hypothesis Task ×2~3 | ✅divergent | **vuln class 불확실할 때만.** 상한 3, 초과분은 팬아웃 말고 순차로 좁힘 |
| P3 Primitive | 단일 Task/오케스트레이터 | ❌수렴 | leak/AAW는 순차 의존 — 병렬해도 안 빨라짐 |
| P4 Exploit 체이닝 | 오케스트레이터 단독 | ❌ | primitive 전부를 한 컨텍스트에. `from primitives import *`로 조립(파편화 금지) |
| P5 Verify | skeptic Task ×1 | ✅반증 | SOLVE 선언 전 refute: leak 위양성(`0x4c4c..`/`0x4747..`/safe-linking 키 `chunk>>12`)·libc mismatch·local↔remote 차 |

- **spawn**: P1=큰 읽기 발생 시 무조건 위임 / P2=class를 1개로 못 좁힐 때만(상한 3) / P5=SOLVE 선언 전 항상 skeptic 1개.
- **kill/prune**: 가설 Task가 무효화 사실 발견→즉시 `state alert`→오케스트레이터가 **같은 경로 타던 Task 조기종료·재시드**. `state no ... -- <이유>`로 dead-end 기록된 가설은 재투입 금지.
- **절대 팬아웃 금지**: P0 triage·P4 최종 체이닝(컨텍스트 파편화 손해).
- **stop-loss**: easy-tier 20분 / hard는 대회일 무제한이되 무진전 시 오케스트레이터 **take-over**(직접 bash가 Task transport보다 안정).
- **서브에이전트 작업지시 기본**: "진입 즉시 `state show` 읽어라 + 끝나면(성공/막힘 불문) 결론을 `state`에 append + `pkshare`."

## 다중 에이전트 · 상태 공유 규약 (데이터 버스 — 도구 강제)
버스 = 챌린지 디렉토리의 STATE.jsonl (append-only, flock 병렬안전, 에이전트 사망에도 영속). 도구 `state`.
- 진입 즉시 `state show` (무효화 ALERTS 먼저 확인). checkpoint/종료마다 배운 것 append:
    state offset <k> <v> [src]   # pwndbg/readelf 실측 오프셋만
    state ok   <text>            # 로컬 실증된 primitive/step
    state no   <text> -- <이유>  # 막힌 것 + 이유 (재시도 금지)
    state next <text>            # 다음 한 걸음
    state alert <text>           # 모두의 계획을 바꾸는 무효화 사실 (예: show 단발→그 route 전멸)
                                  #   -> 발견 즉시(다음 행동으로 넘어가기 전) 기록, "checkpoint까지 미루기" 금지.
                                  #   병렬 에이전트가 이미 죽은 경로에 시간 쓰는 걸 막는 게 목적.
                                  #   대화/보고에서 이 사실을 언급하는 순간 = STATE에 쓰는 순간이어야 함(순서 반대=위반).
- 모델: 파일=단일 진실원(pull). 브로드캐스트는 오케스트레이터가 중계 — `alert` 감지 시 영향 에이전트 재시드/조기종료. peer-to-peer push 안 함(수신자 사망 시 유실).
- 오케스트레이터는 미검증 가정을 프롬프트에 박지 말 것 → STATE에 쓰고 "state show 읽어라"로 위임(오시드 오염 방지).
- **(한계 인정)** "즉시 기록"은 문구만으론 매 순간 보장 안 됨 — `pkshare`/handoff 직전 `state show`로
  "대화 중 언급됐던 무효화급 사실이 다 들어갔는지" 최종 대조가 최후 안전망 (아래 "팀 공유물" 절 참조).

## gdb 구조화 출력 (pwndbg 노이즈 대신 데이터)
- exploit.py: `import pwnkit` → `gs = pwnkit.CLEAN_GS + pwnkit.snapscript([("rip","$rip"),("tgt","*(void**)%d"%a)]) + "\ncontinue\n"` → 'SNAP k=v' 핀포인트만.
- 필터: `... | pwnclean`(ANSI/배너/systemd/빈줄 제거) · `... | pwnclean --kv`(SNAP/PWNED/flag/uid/$ 신호만). grep -v 수작업 반복 금지.
- 왕복 최소화: 여러 값은 한 번의 scripted gdb로 batch 방출(비용은 출력크기 아닌 round-trip이 지배).

## 재도출 금지 (measure-once / import-once)
- 정적 오프셋(symbol/gadget, ASLR 무관): `state offset`(또는 코드서 `pwnstage.set_offset`)로 버스에 저장 → 코드는 `pwnstage.offsets()`/`state get <k>`로 읽어 **readelf/ROP 재실행 금지**.
- 런타임 primitive(heap_base/libc_base/arb_write 등): 검증되면 챌린지 디렉토리 `primitives.py`에 함수로 노출(`pwnstage scaffold`로 스켈레톤). 형제/후속 에이전트는 재작성 말고 `from primitives import *`로 조립 → 각 에이전트 컨텍스트↓ + 재도출 왕복↓.

- **headless(SSH) gdb**: `gdb.debug(gdbscript=)`는 터미널 필요→SNAP 유실. `pwnkit.run_batch(binary, snapscript([...])+"break..\nrun\n..", stdin=b"..")`(gdb -batch) 또는 `gdb.debug(...,api=True)` 사용.

## 속도 프로파일 (easy-tier: pwnable.kr ≈20분 목표)
pwnable.kr류는 이제 easy-tier → 문제당 ~20분 내 목표. 20분을 먹는 건 timeout이 아니라 (사망·재투입/과잉숙고/왕복). 레버를 함께:
- **timeout 축소(fail-fast)**: gdb/python `timeout 30`(기존 90), pwntools `ssh(...,timeout=10)`. hang 오래 안 기다림.
- **모델**: easy-tier=**sonnet 기본**(빠름), fable은 진짜 hard heap(FSOP/safe-linking 등)만.
- **STATE 선-시드**: 오케스트레이터가 소스로 vuln 먼저 도출→STATE에 넣음→에이전트는 실행만(turn 최소).
- **20분 stop-loss + take-over**: 20분/무진전이면 오케스트레이터가 직접 마무리(내 bash가 에이전트 transport보다 안정) 또는 다음으로.
- **batch 왕복**: 여러 gdb 값은 `pwnkit.run_batch` 한 번에. solve.py는 파일로 쓰고 실행(인라인 중첩 금지).

## 팀 공유물 (본선 팀전 — 성공=writeup, 막힘=handoff)
- **SOLVE 시**: `pkshare` → `WRITEUP.md`. **WRITEUP은 최종 체인만이 아니라 풀이과정(정찰→분석→primitive→체이닝, 시도·배제·핵심착상을 진행 순서대로) 포함해야 함.** 그래서 작업 중 STATE에 과정을 기록(ok=된 것/no=배제+이유/alert=전환점/offset=측정) → pkshare가 append 순서를 풀이과정으로 렌더. 팀 복기+유사문제 재활용.
- **막힘/stop-loss 시**: `pkshare` 실행 → `SHARE.md`(막힌 지점·배제목록·다음단계·현 스크립트) → **팀원(또는 다른 모델)이 이어받기**. STATE 최신 유지가 곧 공유 품질(pkshare는 STATE.jsonl을 렌더할 뿐).
- **`pkshare` 실행 직전 `state show`로 최종 대조**: 대화 중 언급된 무효화급 발견이 STATE에 다 들어갔는지 확인.
  (pkshare는 STATE.jsonl을 그대로 렌더할 뿐이라, 빠진 게 있으면 공유물도 그대로 빠짐.)
- 에이전트 작업지시 기본 포함: "끝나면(성공/막힘 불문) pkshare로 공유물 남겨라."

## 도구 회귀검증
- 도구(state/pwnkit/pwnstage/pkstart/pkshare/pkflag) 수정 후 `pkselftest` 한 방 실행 → ALL GREEN 확인 (kernel testkit 패턴 이식).
- 큰 gdb/heap 상태는 항상 파일로 빼고 grep(인라인 덤프 금지). 제공된 run.sh/Dockerfile 실행조건은 재발명 말고 그대로 미러.
