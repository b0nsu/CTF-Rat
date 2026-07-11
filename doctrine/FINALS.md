# FINALS 배틀플랜 (결승 — 팀전 · 실 remote flag · 문제 다수)
> `이 레포 루트에서 `claude`(또는 codex)` 진입 시 이 문서 + CLAUDE.md(ROE 최상단) 먼저 읽고 따를 것.

## 0. 개전 (첫 5~10분)
- PATH 확인: `export PATH=$HOME/ctf/bin:$HOME/.local/bin:$PATH` (recon/decomp 등 래퍼 즉시 사용).
- ⛔ ROE 재확인: **지정 단일 타겟만**. 타 팀/호스트/인프라 금지.
- 챌린지 목록 + 접속정보(바이너리·nc host:port·ssh) 확보.
- 전 문제 `pkstart <name> <binary>` 일괄 온보딩(recon→STATE 정적 시드).

## 1. 트리아지 & 우선순위 (SOLVABILITY 게이트)
- recon 후 tier: 확신(SOLVE) / 작업필요(STANDARD) / 후순위(SKIP).
- 우선순위 = **확신도 × 배점 ÷ 예상난이도** → 확신되는 고배점 먼저.
- 미준비 아키·범위밖·저확신 = 후순위. **커널 나오면 `kernel/` 레이어**(run_qemu/repack/dump_heap 등, 별 세션서 구축·Kaleido 실증).
- 팀 분담: Claude 담당 vs 팀원 담당 나눠 STATE/pkshare로 공유.

## 2. 문제당 고정 루프
`pkstart` → `state show` → decomp/도출(**honest: 답/writeup 검색 금지, 바이너리서 도출**) → primitive **live 실증**(`pwnkit.run_batch`) → 체인 조립(오프셋은 `pwnstage.offsets()`) → **로컬 재현** → **remote 실flag** → `pkshare`(WRITEUP).
- 배운 것은 진행하며 STATE에 `offset/ok/no/alert` 기록(사망 내성 + 팀 공유).

## 3. 모델 라우팅 (모델=도구, 오케스트레이터가 triage)
- 기본 **sonnet**: easy/medium 정형(bof/ret2libc/fmt/단순heap) — 빠르고 싸게 폭 확보.
- **opus**: hard heap·창의적 다단계·**결정성 필요(remote 신뢰성)**. sonnet 막히면 승격. (실증: heapnote — sonnet 5-hop/50%retry vs opus position-independent 2/2)
- 최난/불확실: **multi-hypothesis fan-out**(서로 다른 경로 병렬 — 하나 죽어도 가설 수렴/완주).
- **문제 간 병렬**: 문제당 1에이전트로 2~3개 동시(박스/ transport 여유 내). 오케스트레이터가 감시.

## 4. 회복탄력성 (결승 필수)
- 항상 **checkpoint-to-disk**(solve.py/STATE). 에이전트 사망은 흔함 → 죽으면 오케스트레이터가 **harvest + take-over**.
- 스톨(무진전/재분석 반복) → take-over 또는 fan-out. 질질 X.
- gdb는 **scripted+timeout(`run_batch`)**, interactive 금지(watchdog 사망).
- 미검증 시드 프롬프트에 박지 말 것(가설로만) — 에이전트가 live 검증 주도(leakme 교훈).

## 5. 제출 규율 (치명적 — 오제출 방지)
- **flag는 remote 실서버서 획득 + 2회 재현 후에만 제출.** 로컬 placeholder(예 flag{fake_flag}) 아님.
- **flag 포맷 검증(당일)**: 오케스트레이터가 flag 타입/포맷 수령 → `pkflag --set '<정규식>'`. 캡처 flag는 `pkflag <flag>`로 **REAL 확인 후에만 제출**(포맷 불일치 / fake·test·example·dummy 등 placeholder 자동 배제).
- 오케스트레이터가 **독립 재현으로 확정**한 것만 "제출 가능"으로 팀에 넘김.

## 6. 팀 협업
- solve → `pkshare` = `WRITEUP.md`(취약점·체인·오프셋·재현) 팀 공유+복기.
- 막힘 → `pkshare` = `SHARE.md`(막힌지점·배제목록·다음단계·현스크립트) → 팀원/다른 모델 이어받기.
- `STATE.jsonl` = 공유 지식 단일원.
- **팀 실시간 공유(4-AI)**: `doctrine/SOLVING.md(팀 공유 절)` 세팅(각자 1회) → 문제마다 `teamreg <문제> <bin>` 등록, `teamsync --loop &` 켜고, `teamstate <문제>`로 팀 통합 진행(검증오프셋·배제·착상) 확인. 남이 구한 것/배제한 dead-end 재작업 방지.

## 7. 도구 요약 (bin)
recon·decomp·pkstart(온보딩) / state(지식버스)·pwnkit+pwnclean(구조화 gdb)·pwnstage(재도출캐시) / pkshare(공유물) / (커널) kernel/ 레이어.
