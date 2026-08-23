# CTF-Rat v2 로드맵 — 실행 계획 인덱스

목표: **엄격한 CTF 절차 프레임워크 → 빠른 분석 Query Engine + 필요할 때만 엄격한 Verification Engine.**
증상(컨텍스트 빨리 참 + 느림)의 90%는 새 도구가 아니라 진입점·컨텍스트 정책·캐시 배선 문제.

## 핵심 원칙
- **측정 먼저**: 각 마일스톤 끝에 telemetry A/B. "느낌상 빨라짐" 금지.
- **순수 배선 우선**: 새 분석 능력 0개로 얻는 win(M1/M2)이 최우선.
- **기존 것 재사용**: 새 state DB / 새 캐시 / 새 decompiler / auto-exploit gen 금지.
- **레포 게이트 유지**: 비프로모션(`promotion_allowed:false`), honest-mode, 단일 명시 대상, digest provenance.

## Canonical 설계 spec
[DESIGN_v2.md](DESIGN_v2.md) — 아키텍처 설계서(`CTF-Rat_v2_Architecture_Design_KO.pdf`)를 레포 binding spec으로 정착.
불변식·계약(C1~C10)·release gate·ADR·migration을 담는다. **M0~M4는 이 spec에 매핑되며, 충돌 시 DESIGN_v2가 우선.**

## 마일스톤 (설계서 PR1~PR6 매핑)
| ID | 파일 | 요지 | 예상 | 브랜치 | 설계서 |
|---|---|---|---|---|---|
| M0 | [M0-telemetry.md](M0-telemetry.md) | 계측 기반 — operation_fingerprint·benchmark v2 필드 | 2~3h | `feat/m0-telemetry` | PR1 |
| M1 | [M1-slim-entrypoint.md](M1-slim-entrypoint.md) | 슬림 진입점 + FAST/DEEP + state compact 우선순위 + governor | 반나절 | `feat/m1-slim-entrypoint` | PR2/PR4 |
| M2 | [M2-cache-unify.md](M2-cache-unify.md) | 통합 캐시 + hit envelope fix + dual-read/single-write | 반나절 | `feat/m2-cache-unify` | PR3 |
| M3 | [M3-rev-features.md](M3-rev-features.md) | oracle wiring + Function Card v2 + data slice MVP | 1~2일 | `feat/m3-rev-features` | PR6 |
| M4 | [M4-front-door.md](M4-front-door.md) | `rat` dispatcher + operator skills + query envelope | 1일 | `feat/m4-front-door` | PR5 |
| M5 | (조건부) | difftrace/constraint/pwn observers — telemetry 병목 증명 후 | — | `feat/m5-*` | PR7 |

> difftrace는 P0가 아니라 **P2 1순위**(설계서 §16). Function Card compare_sites+oracle wiring이 먼저 대체하므로 M3 후 telemetry로 재판정.

## Release Gate (DESIGN_v2 §21 — 채택 판정)
하드 게이트: **false SOLVED=0**, **verified solve rate ≥ v1**. 효율 target: TTF ≤70%, peak context ≤55%, tokens ≤65%, duplicate ≤25%, warm cache hit ≥70%, easy-REV unnecessary-DEEP ≤10% (모두 vs v1 baseline).

## 검증 환경 (준비 완료)
설계서 §20이 요구하는 "고정 env"는 `docker/dev`(브랜치 `chore/dev-env`) — Linux x86_64 + angr 9.2.213/pwntools/gdb 12.1.
baseline: 컨테이너 unittest 121/123(2개 non-blocking: qiling 옵션·pwncrash 에뮬). 모든 benchmark는 이 컨테이너에서.

## 브랜치 규칙
- 계획 문서: 이 `plan/roadmap` 브랜치.
- 각 마일스톤 구현: `main`에서 `feat/m<N>-<slug>` 새 브랜치를 판다.
- 마일스톤 완료 = plan의 완료기준(Acceptance) 전부 GREEN + telemetry A/B 증거 기록.
- push/merge는 사람이. 커밋은 해당 feat 브랜치에만.

## 순서 게이트 (설계서 핵심 순서)
```
measure → slim → unify cache → compact context → query front door → oracle wiring → bounded data slice
  M0        M1        M2          (M1-4/M3)          M4                M3               M3
```
한 PR=한 가설. 동일 corpus/env/timeout에서 cold/warm 분리 측정. 앞 단계 개선이 telemetry로 증명되기 전엔 다음 착수 금지.
verified_solve가 하락한 실험은 토큰/속도가 좋아도 **채택 금지**(하드 게이트).
