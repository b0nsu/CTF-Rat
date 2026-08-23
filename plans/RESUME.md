# 재개 포인트 (새 세션용)

이 파일 하나만 읽으면 어디서 멈췄고 다음에 뭘 하는지 안다.

## 지금까지 (계획·준비 완료, 구현 착수 전)
- **전략 확정**: CTF-Rat v2 = Query-First Solver Runtime. 순서 `measure → slim → unify cache → compact → front door → oracle → slice`.
- **계획 문서**: `plans/`에 전부 있음 (브랜치 `plan/roadmap`, 커밋 `0a0fecf`).
  - `DESIGN_v2.md` = canonical binding spec (불변식·계약 C1~C10·release gate·ADR·migration). **충돌 시 이게 우선.**
  - `README.md` = 인덱스 + PR매핑 + release gate + 순서 게이트.
  - `M0`~`M4` = 마일스톤별 세부(현재상태/작업/Acceptance/설계서 반영/완료게이트/롤백).
  - 원본 설계서 PDF 보존.
- **검증 환경 준비 완료**: 브랜치 `chore/dev-env`(커밋 `b769c91`). `docker/dev`에 Linux x86_64 컨테이너(angr 9.2.213/pwntools/gdb 12.1). baseline 121/123(2개 non-blocking: qiling 옵션·pwncrash 에뮬).
  - Colima `default`(x86_64, 4C/8G) VM 사용. 빌드 `docker/dev/build.sh`, 셸 `docker/dev/shell.sh`, 테스트 `docker/dev/test.sh`.

## 다음 액션 (M0부터)
1. **브랜치 정리**: `plan/roadmap` + `chore/dev-env`를 로컬 `main`에 머지(push는 사람). → feat 브랜치가 plans+컨테이너 상속.
   ```sh
   git checkout main
   git merge --no-ff plan/roadmap chore/dev-env
   ```
2. **M0 착수**: `git checkout -b feat/m0-telemetry`. `plans/M0-telemetry.md` 완료게이트대로 구현.
   - M0-1 tool-result envelope에 `tool_name/params_digest/cache_state` + **hit 브랜치 `cache.hit=true` 보정**(`contracts.py:30-35`).
   - M0-2 `bin/rat-metrics`(operation_fingerprint 기반 duplicate/cache/ttf, read-only).
   - `rat.benchmark-result.v2.json` + `tests/test_telemetry.py`.
   - M0-3 컨테이너에서 baseline jsonl(cold/warm).
3. 모든 검증·측정은 `docker/dev` 컨테이너 안에서. 앞 마일스톤 telemetry 증명 전 다음 착수 금지.

## 핵심 결정 메모
- difftrace는 **P0 아님 → P2 1순위**(설계서 §16). Function Card compare_sites+oracle wiring이 먼저 대체.
- 새 state DB/cache/decompiler/full taint/generic auto-exploit/semantic auto-inject = **금지**(ADR).
- 브랜치 규칙: 마일스톤마다 `feat/m<N>-<slug>` 새로. push/merge to remote는 사람만.
- 캐시 버그 교차검증됨: `contracts.py` cache hit 시 옛 envelope 그대로 반환 → `hit=false` 남음. M0/M2에서 수정.
