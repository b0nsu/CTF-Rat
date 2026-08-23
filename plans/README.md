# CTF-Rat v2 로드맵 — 실행 계획 인덱스

목표: **엄격한 CTF 절차 프레임워크 → 빠른 분석 Query Engine + 필요할 때만 엄격한 Verification Engine.**
증상(컨텍스트 빨리 참 + 느림)의 90%는 새 도구가 아니라 진입점·컨텍스트 정책·캐시 배선 문제.

## 핵심 원칙
- **측정 먼저**: 각 마일스톤 끝에 telemetry A/B. "느낌상 빨라짐" 금지.
- **순수 배선 우선**: 새 분석 능력 0개로 얻는 win(M1/M2)이 최우선.
- **기존 것 재사용**: 새 state DB / 새 캐시 / 새 decompiler / auto-exploit gen 금지.
- **레포 게이트 유지**: 비프로모션(`promotion_allowed:false`), honest-mode, 단일 명시 대상, digest provenance.

## 마일스톤
| ID | 파일 | 요지 | 예상 | 브랜치 |
|---|---|---|---|---|
| M0 | [M0-telemetry.md](M0-telemetry.md) | 계측 기반 — cache_hit/duplicate/time_to_flag 실측 | 2~3h | `feat/m0-telemetry` |
| M1 | [M1-slim-entrypoint.md](M1-slim-entrypoint.md) | 슬림 진입점 + FAST/DEEP + rat route | 반나절 | `feat/m1-slim-entrypoint` |
| M2 | [M2-cache-unify.md](M2-cache-unify.md) | 통합 캐시 read-through 인덱스 | 반나절 | `feat/m2-cache-unify` |
| M3 | [M3-rev-features.md](M3-rev-features.md) | oracle→symsolve, difftrace, function-card v2 | 1~2일 | `feat/m3-rev-features` |

## 브랜치 규칙
- 계획 문서: 이 `plan/roadmap` 브랜치.
- 각 마일스톤 구현: `main`에서 `feat/m<N>-<slug>` 새 브랜치를 판다.
- 마일스톤 완료 = plan의 완료기준(Acceptance) 전부 GREEN + telemetry A/B 증거 기록.
- push/merge는 사람이. 커밋은 해당 feat 브랜치에만.

## 순서 게이트
```
M0(baseline 확보) ─▶ M1(context_peak↓ 증명) ─▶ M2(duplicate↓ 증명) ─▶ M3(solve rate/ttf↑ 증명)
```
앞 단계 개선이 telemetry로 증명되기 전엔 다음 단계 착수 금지.
