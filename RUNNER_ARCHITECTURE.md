# ctf-rat 아키텍처 — pwn/rev 집중형 (확정 설계 v1)

> 작성: 2026-07-11 세션. dding-skills를 참고하되 **"여러 문제 × worker/queue 자동루프"를
> 버리고 "한 문제 × phase별 fan-out/converge"로 뒤집은** 설계. §1.9 전략("한 문제씩 집중
> 투입") 위에 세움. 이 문서 = 빌드 청사진. 확정 후 (a) doctrine은 `CLAUDE.md`로 전사,
> (b) 신규 코드(L1 어댑터·rev 루프·callback·run manifest)는 `bin/`에 구현.

---

## 0. 확정 결정 (locked)

| 축 | 결정 | 함의 |
|---|---|---|
| 서브에이전트 엔진 | **Claude Task 서브에이전트만** | 멀티모델 transport·프롬프트 조율 불필요. P2 팬아웃·P5 verify 전부 Claude Task. 컨텍스트 공유는 STATE 버스 |
| L1 Ingest 범위 | **Dreamhack/CTFd pull → `newchal` 자동. flag 제출 수동** | fetch·정찰까지만 자동. 제출은 사람(ToS + honest-mode 보호) |
| 오케스트레이터 | **이 레포에서 구동되는 Claude 세션 + Task tool. 별도 코드 없음** | phase state machine = CLAUDE.md **프로토콜**. Claude가 규약대로 Task를 spawn/kill. 사용자 관전 모델과 일치 |

**검증단계 자유결정 (v1, 2026-07-11):** ① P2 팬아웃 상한=3 하드, 초과분은 팬아웃 말고 순차로 좁힘(조율비용 폭증 방지). ② 빌드순서 ①(doctrine 전사)를 최우선 확정 실행, rev 루프 우선순위는 실전 몇 문제로 pwn:rev 비율 확인 후 재조정. — 실전 피드백으로 언제든 개정 가능.

---

## 1. 설계 원칙

1. **한 번에 활성 문제 1개.** 문제-간 자동 배분(lease/queue/stale-reclaim)은 만들지 않는다.
2. **팬아웃은 문제 "안"에서만.** vuln class 불확실성을 좁히거나 verify 확신을 올릴 때. 문제-간 팬아웃 금지.
3. **컨텍스트 위생 우선.** 큰 읽기(대형 함수 decomp/strings/xref)는 항상 서브에이전트로 빼고 결론만 회수.
4. **파일 버스가 단일 진실원.** 에이전트끼리 직접 대화 없음. 전부 STATE.jsonl 경유 + 오케스트레이터가 alert 중계.
5. **재발명 금지.** 기존 도구(`state`/`newchal`/`recon`/`decomp`/`pwnkit`/`pwnstage`/`primitives.py`/SOLVABILITY/GROUNDING_INDEX/`pkshare`)를 그대로 재사용. 신규는 최소.

---

## 2. 전체 그림 (3계층)

```
┌─ L1 INGEST (dding에서 차용하는 유일한 겹) ─────────────────────────┐
│  ctfpull <platform> <event|url>  →  문제 메타 pull  →  newchal 자동   │
│  ※ flag 자동제출 없음. 수집·스캐폴드까지만.                            │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼  (활성 문제 1개)
┌─ L2 SOLVE (100% 커스텀, 본체) ──────────────────────────────────────┐
│  단일 문제 6-phase state machine (CLAUDE.md 프로토콜)                  │
│  오케스트레이터(Claude) = 상태·판단·spawn/kill·take-over          │
│  서브에이전트(Claude Task) = scout / hypothesis / skeptic             │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌─ L3 SHARE/VERIFY (기존 확장) ───────────────────────────────────────┐
│  STATE.jsonl 버스 + primitives.py + adversarial verify + pkshare      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. L1 INGEST — `ctfpull` 어댑터 (신규, dding 차용)

**역할:** 대회 연결 + 문제 메타를 당겨 `newchal` 스캐폴드로 떨군다. 그게 전부.

```
ctfpull dreamhack <challenge-url|id>     # Dreamhack 어댑터
ctfpull ctfd <base-url> [--list|<id>]    # CTFd 어댑터
   → 문제 메타(name, category, files, nc host:port) 파싱
   → 첨부 다운로드
   → newchal <name> <bin> [libc] [host:port] 호출 (기존 스캐폴드 재사용)
   → run.json 초기화 (§6.3)
```

- **제출 안 함.** dding의 flag 자동제출·VM live-control은 이식하지 않는다.
- **worker/queue 안 씀.** 문제 목록만 뽑고, 실제 투입은 사람이 하나씩 선택.
- 인증 토큰은 기존 `.ctfd.env` 패턴 재사용(git 미추적, 시크릿 로컬 영속).

---

## 4. L2 SOLVE — 단일 문제 6-phase state machine (본체)

각 phase마다 **fan-out을 켜고 끄는 규칙이 고정**돼 있다. 이게 서브에이전트 배치/투입/제외의 답.

| Phase | 주체 | fan-out | 규칙 |
|---|---|---|---|
| **P0 Triage** | 오케스트레이터 단독 | ❌ | `recon`+triage rubric. 전역 시야 필요. 여기서 팬아웃 = 조율비용 낭비 |
| **P1 RE/정찰 위임** | scout Task × N | ⚠️ 위임(≠팬아웃) | context-heavy 읽기는 **항상** Task로. 결론만 STATE 회수. 기존 "큰 읽기는 subagent" 규칙의 강제화 |
| **P2 Vuln 가설** | hypothesis Task × 2~3 | ✅ **핵심 divergent** | **vuln class 불확실할 때만.** 각자 다른 가설 병렬. 확실하면 팬아웃 없이 바로 실행 |
| **P3 Primitive** | 단일 Task or 오케스트레이터 | ❌ 수렴 | leak/AAW 확보는 순차 의존. 병렬해도 안 빨라짐 |
| **P4 Exploit 체이닝** | 오케스트레이터 단독 | ❌ | primitive 전부를 한 컨텍스트에. 파편화가 해로움. `primitives.py` import 조립 |
| **P5 Adversarial verify** | skeptic Task × 1 | ✅(반증) | SOLVE 선언 전 refute 시도. leak 위양성·libc mismatch·local↔remote 차 |

### 4.1 spawn 트리거
- **P1 진입**: 컨텍스트 터질 읽기 발생 → scout Task 위임 (무조건).
- **P2**: triage가 vuln class를 **1개로 못 좁힘** → 가설 수만큼 팬아웃, **상한 3**(초과 시 조율비용 > 이득).
- **P5**: 항상 skeptic Task 1개. 프롬프트 = "이 exploit을 반증하라"(refute 지향). nvv 3-way가 "정직한 no-flag"를 증명한 패턴을 verify로 재사용.

### 4.2 prune/kill 트리거
- 가설 Task가 **무효화 사실** 발견 → 즉시 `state alert` → 오케스트레이터가 **같은 경로 타던 Task 조기종료·재시드** (nvv `_exit`→FSOP 전멸이 정확히 이 케이스).
- `state no <text> -- <이유>`로 dead-end 기록된 가설은 **재투입 금지**.
- **stop-loss**: easy-tier 20분 / hard는 대회일 무제한이되 무진전 시 오케스트레이터 **take-over**(직접 bash가 Task transport보다 안정).

### 4.3 절대 팬아웃 금지 구역
- **P0 triage · P4 최종 체이닝.** 여러 에이전트 = 컨텍스트 파편화로 손해.

---

## 5. L3 SHARE/VERIFY — STATE 버스 (기존, 재발명 없음)

- **버스 = `STATE.jsonl`** (append-only, flock 병렬안전, pull 모델, 에이전트 사망에도 영속).
- **`primitives.py`** = 검증된 런타임 프리미티브 단일 진실원 (import-once, 재도출 금지). 형제 Task는 `from primitives import *`.
- **broadcast는 오케스트레이터만 중계.** peer-to-peer push 금지(수신자 죽으면 유실). 미검증 가정을 프롬프트에 박지 말고 "state show 읽어라"로 위임.
- **verify → pkshare**: SOLVE=WRITEUP(풀이과정 포함), 막힘=SHARE(배제목록+다음단계). `pkshare` 직전 `state show`로 최종 대조.

---

## 6. 추가 시스템 (신규 추천)

### 6.1 rev 전용 루프 ⭐ 최우선
현재 셋업은 pwn 편중. rev 대칭 루프 신설:
- **`revq`** — 정적 분석 배치(함수 목록·xref·string refs를 컨텍스트 밖으로).
- **angr/symbolic 하니스** (angr — SETUP.md) — 제약 풀이 위임용 스캐폴드.
- **VM-lifter 스캐폴드** — custom VM 만나면 opcode 표 자동 추출→재구현(license_checker 경험 템플릿화).
- **decompile→요약 Task 패턴** — 대형 함수를 Task가 요약해 회수.

### 6.2 callback listener 데몬 (dding에서 이것만 차용)
blind leak/SSRF용 threaded HTTPServer. `pwnkit`와 연계, `--live` 게이트.

### 6.3 run manifest — `run.json`
문제마다 `{binary_hash, libc, host:port, protections, 최종 exploit 경로, flag}` 자동 기록. writeup·재현 자동화. dding lifecycle 중 이 얇은 겹만 차용.

### 6.4 budget/stop-loss governor
phase별 시간·토큰 상한 + 초과 시 take-over 신호. throughput 규율의 자동화(문서/프로토콜로 시작, 반복되면 코드화).

---

## 7. 코드 vs 프로토콜 분류

| 항목 | 구분 | 위치 |
|---|---|---|
| phase state machine, fan-out/converge 규칙, spawn/prune 트리거, STATE 사용법, stop-loss | **프로토콜(코드 X)** | `CLAUDE.md`에 전사 |
| `ctfpull` (Dreamhack/CTFd 어댑터) | 신규 코드 | `bin/ctfpull` |
| `revq` + angr 하니스 + VM-lifter 스캐폴드 | 신규 코드 | `bin/`, `solve/_template/` |
| callback listener 데몬 | 신규 코드 (dding 디자인 참고) | `bin/pwncallback` |
| `run.json` writer | 신규(얇음) | `newchal`/`ctfpull`에 통합 |
| STATE 버스·newchal·recon·decomp·gdbq·pwnkit·pwnstage·primitives.py·SOLVABILITY·GROUNDING_INDEX·pkshare/pkflag | **재사용(그대로)** | 기존 |

---

## 8. 권장 빌드 순서

1. **doctrine 전사** — 본 문서 §4·§5를 `CLAUDE.md`에 "다중 에이전트 phase 프로토콜" 절로 추가. (코드 0, 즉시 실전 투입 가능)
2. **`ctfpull` CTFd 어댑터** — CTFd가 API 표준이라 먼저(Dreamhack은 인증 복잡). newchal 연동 + run.json.
3. **rev 루프 스캐폴드** (`revq` + `solve/_template` rev 버전) — pwn 편중 해소.
4. **`ctfpull` Dreamhack 어댑터** — 기존 dding 어댑터 참고.
5. **callback listener + budget governor** — 실전에서 필요성 확인되면.

> §7 원칙: 반복되는 프로토콜만 나중에 코드화(승격). 처음부터 오케스트레이터를 Python으로 굳히지 않는다(CTF는 예측불가 → 과설계 위험).
