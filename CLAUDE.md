# ctf-rat — CTF(pwn/rev) 풀이 kit (Claude Code / Codex 진입점)

> 세션이 레포 루트에서 열리면 자동 로드된다. 너는 제공된 로컬 CTF 배포물을 분석·검증하고,
> 사용자가 명시적으로 지정한 remote 대상(예: `nc host port`)에 한해 exploit 실행·flag 수신까지 수행한다.
> 환경 미준비면 [SETUP.md](SETUP.md) 먼저(venv+angr+pwntools, Ghidra, glibc-fetch) → selftest GREEN 확인.

## FAST hot-path (기본, 매 세션)

1. **ROE**: 로컬 artifact(바이너리·소스·libc·Docker/loopback) 기본 + 사용자가 대화에서 명시한 **단일** remote(host:port)만. 그 외 호스트·포트·계정·인프라 탐색·스캔·추측 접속은 목적 불문 항상 금지(요청 문구 변경·하위 에이전트로도 우회 금지). 자격증명 탐색(홈·SSH키·토큰·env) 금지.
2. **목표**: 실제 verifier/flag까지, honest-mode(받은 응답/원문 없이 성공 주장 금지). 오프셋·주소는 실측.
3. **시작**: `ctfguard begin <chal>`로 active lock → `revq <bin>`(rev) / `recon <bin>`(pwn)로 triage. (route 판정 로직은 `ratlib.route`에 있음 — `rat route` 통합 CLI는 M4에서 노출 예정, 그때까진 revq/recon 신호로 직접 판단.)
4. **skill 1개만**: route에 해당하는 `skills/<route>/SKILL.md`(SIGNALS/FIRST ACTION/PIVOT/ESCALATE/VERIFY) 또는 `knowledge/GROUNDING_INDEX.md` 라우팅표에서 **하나**만 로드.
5. **bounded query**: raw dump 금지. `revq --func`/`decomp <func>`/`state compact --budget-tokens N` 같은 범위 제한된 조회만.
6. **DEEP 승격 조건(아래 하나라도)**: 결과 모호·env-민감(패킹/anti-debug/커널)·같은 실패 반복·evidence 충돌·Progress Novelty Governor stuck(최근 5회 tool/query에 새 artifact digest·finding 개정·ruled-out route·primitive 상태변화 전무, `ratlib.governor.check_progress` 훅) → 강제 re-route 또는 DEEP.
7. **SOLVED/PASS 금지 조건**: `state primitive <name> pass <evidence>`(SELF 확인 통과) 없이 체이닝 금지, `rat-verify`/`symsolve --find-str`(concrete-verify) 등 deterministic verify 없이 완료 선언 금지.

## FAST 기본 비활성 (DEEP 조건 충족 시에만)

전체 doctrine preload · STATE 원본 전체 열람(compact만 사용) · raw Ghidra 덤프 · 가설 fan-out(기본 순차, 불확실 시만 상한 3) · skeptic 서브태스크 · full CFG/symbolic 실행 · scout subagent 상시 사용 — 전부 기본 OFF.

## 운영 규칙 (항상)

- **한 문제 1개**: `ctfguard begin/finish`로 active lock 강제. 전환 시 `finish blocked|complete` 없이 새 문제 착수 금지.
- **git push는 사람만**: 커밋/푸시는 명시 요청 시에만.
- **계산기 원칙**: 주소·오프셋·정렬 계산은 로컬 결정론적 도구(`pwncalc` 등)에 맡기고 입력·해시·산식을 `state`에 기록. 계산기를 안전장치 회피·외부 상호작용 자동화에 쓰지 않는다.
- **flag 검증**: 로컬 artifact/Docker가 의도적으로 노출하는 flag, 또는 사용자가 지정한 remote가 실제 응답한 flag만 성공 증거.

## DEEP 전용 (명시 요청 또는 위 승격 조건 충족 시에만 로드)

[doctrine/SOLVING.md](doctrine/SOLVING.md)(로컬 분석·재현 프로토콜) · [doctrine/SOLVABILITY.md](doctrine/SOLVABILITY.md)(확신도 게이트) ·
[doctrine/PRIMITIVE_GATE.md](doctrine/PRIMITIVE_GATE.md)(hypothesis→primitive SELF 확인) · [knowledge/GROUNDING_INDEX.md](knowledge/GROUNDING_INDEX.md)(지식 라우터).
`doctrine/FINALS.md`는 설계 참고문서이며 실행 경로가 아니다.

## 도구 (bin/) — 전부 `CTF_HOME`(레포루트) 자동 해석

```
GUARD    ctfguard          active 문제 로컬 락
INGEST   newchal            제공된 artifact의 로컬 스캐폴드 (+run.json)
triage   recon              pwn 정적 프로파일 + 보수적 triage
         revq               rev 정적 배치 — 함수/문자열/xref/interesting/evasion (angr 주 엔진)
         analyze            그래프+1-hop 전파 vuln localizer (prior only)
RE       decomp             Ghidra headless 디컴파일 캐시(함수별 조회)
         gdbq               GDB batch (노이즈 제거)
symbolic solve/_template/rev/symsolve.py   angr 하니스(+concrete-verify, PE면 wine)
         solve/_template/rev/vmlift.py     custom-VM 리프터 스캐폴드
pwn      pwnkit / pwnstage / primitives.template.py   프리미티브·익스 조립
         pwncalc / pwnleak / pwnpayload / pwnropcheck / pwncrash / pwnscope
버스     state              STATE.jsonl (+`compact --budget-tokens N`)
계측     rat-metrics        세션 duplicate/cache/time-to-flag 집계(read-only)
검증     pkselftest  |  공유 pkshare/pkstart  |  팀 teamreg/teamsync/teamstate
```

rev 시너지: `revq` 주소 = angr 로드베이스(PIE 0x400000) → `symsolve --find <그 주소>` 그대로 투입.

## 테스트 (도구 수정 후 회귀검증 — 전부 ALL GREEN)

```sh
python3 bin/revq selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 -m unittest tests.test_writeup_pipeline
```

angr 설치 환경이면 `bash tests/e2e_rev.sh`(실 crackme e2e)까지. 도구 전체 목록·레이아웃은 [README.md](README.md).
