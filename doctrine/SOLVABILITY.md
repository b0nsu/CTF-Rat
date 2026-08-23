# 판단 기준 — "확실히 풀 수 있는가?" (SOLVABILITY)

> **DEEP 전용 문서.** CLAUDE.md FAST hot-path에서는 로드하지 않는다. DEEP 승격 조건 충족 시 또는 명시 요청 시에만 읽는다.

## 목적
시간 제한 분석에서 **근거가 충분한 것만** 끝까지 파고, 확신 없는 건 빠르게 후순위/스킵한다.
오판(확신했는데 못 풂)이 최대 손실 → **높은 정밀도의 보수적 분류기**. 재현율은 희생해도 됨.

## 확신(SOLVE)의 정의 — 가장 중요
1. 눈앞의 **바이너리/소스 분석만으로** 재현 경로를 **스스로 도출**했고,
2. 핵심 **primitive 를 로컬에서 실증**했으며,
3. 남은 체인이 **모든 조각이 확보된** 알려진 템플릿이다.

> 확신의 원천은 "이 챌린지를 안다"가 **아니라** "이 바이너리를 읽고 논리를 재구성했다".

## 하드룰 (오염 금지 — 절대)
- ✅ 허용: 취약점 **개념/기법** 검색·참조 (tcache 원리, fmt GOT overwrite, how2heap 버전별).
- ❌ 금지: 그 챌린지의 **정답 / writeup** 검색 (`<chal> writeup`, `pwnable.kr <x> 풀이` 등).
- 기억나는 상수/오프셋/rand값도 **바이너리·gdb로 재확인 후** 사용. recall 은 부정확 → 실증 필수.
- 이유: recall 기반 "확신"은 오염 → calibration 무효 + 처음 보는 챌린지에 무력 (gnnPwn memorization 문제와 동일).

## 4-게이트 판정 절차
### L0 하드 스킵 (신호 무관 즉시 후순위)
지원하지 않는 플랫폼 / 심한 난독화·anti-analysis / 미준비 아키텍처.

### L1 정적 prior (recon) — 순서용, 판정 아님
`recon` / `triage-all` 로 vuln class 가설 + tier. **확신 아님, 착수 순서만.**
높은 prior: 소스 공개 · win심볼+overflow+noPIE · 직접 fmt · 작고 단일 취약점.

### L2 primitive 게이트 — 진짜 판정
아래 중 하나를 **로컬 실증**해야 확신 상승:
- stack: cyclic → segfault → RIP 제어 오프셋 확정
- fmt/leak: 주소 leak 획득
- heap: 제어된 write / UAF / overlap 확보
"될 것 같다"(정적)는 확신 아님. **실제로 됨**을 봐야 함.

### L3 체인 완성도
primitive + 남은 템플릿 조각 전부 확보?
- 필요한 라이브러리·입력 조건·제어 지점이 모두 확보됐는가?
- 완화기법이 재현 가정을 막지 않는가?
전부 예 → 확신. 조각 하나 빠짐 → STANDARD(작업 필요) 또는 blocker.

### L4 stop-loss (이탈 규칙)
- 예산: 한 챌린지 primitive 실증까지 easy-tier≈20분/hard≈30분 / probe 3라운드.
- 초과 & primitive 없음 → 다운그레이드, 다음 챌린지. (rabbit-hole 방지)
- 막힌 지점 state.md 기록 후 이탈, 나중에 재방문.

## 최종 verdict
```
확신 SOLVE   = L0통과 ∧ L2실증 ∧ L3완성   (L4 예산 내)  → 로컬 재현을 완성한다
SOLVE(작업)  = L0통과 ∧ primitive 유력 ∧ 조각 일부 미확보
후순위/SKIP  = L0스킵 ∨ L4초과 ∨ 미지 blocker
```

## calibration ("확립"하는 법)
라벨 코퍼스(NYU pwn `initial`점수 · pwnable.kr 점수)에서 **정직 모드**(답 미참조)로 도출·실증하며:
- SOLVE 판정의 **정밀도**(확신인데 실패=false positive) 측정 → 최소화하도록 게이트 조정.
- false negative(후순위인데 쉬움)는 허용 — 보수성 우선.
- 기록: `doctrine/calibration.md` 에 [챌린지 · prior tier · 실제 도출 성공? · FP/FN] 누적.
