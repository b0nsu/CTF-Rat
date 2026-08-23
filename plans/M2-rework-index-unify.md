# M2 재작업 — 인덱스 루트 실통합 (single canonical index, 실증)

> **왜(회귀 근거)**: M2(`M2-cache-unify.md`)의 존재 이유는 *"인덱스 하나가 셋을 가리키게 한다"* 인데,
> 실구현은 도구마다 인덱스 루트를 다른 기준으로 앵커링해 일반 레이아웃에서 sqlite 파일이 **2개 이상** 생긴다.
> 그리고 M2-5 통합 검증(`ab_M2.jsonl`)은 `rat-profile` 단독만 측정 → 3도구 공유를 **한 번도 검증하지 않음**.
> = 플랜 명문 목표 **미달성 + 미검증**. (verify + plans 대조로 확정, 2026-08-23)

- **브랜치**: `fix/m2-index-root-unify` (`feat/m3-rev-features` 또는 `main`에서 분기 — 3 참조)
- **예상**: 반나절
- **새 분석 능력**: 0 (인덱스 루트 배선 정정만, M2 원칙 "새 캐시 금지" 유지)
- **선행**: 없음 (M2/M3 위에 얹는 정정)

## 현재 상태 (검증된 사실)

각 도구가 실제로 여는 sqlite (`<root>/indexes/cache.sqlite3`):

| 도구 | 인덱스 루트 앵커 | 코드 |
|---|---|---|
| revq | `dirname(realpath(binary))/.rat` | `bin/revq` (M2 추가분) |
| decomp | `dirname(realpath(cache))/.rat` (== dirname(binary)) | `decomp_cache.py:_register_index` |
| **rat-profile** | `abspath(--store or cwd/.rat)` | `analysis.py:root()` ← **이탈원** |

실증(바이너리 `dist/chal`, 표준 store `./.rat`): revq/decomp → `…/dist/.rat/…`, profile → `…/.rat/…` = **2 파일**.
바이너리가 cwd 직속이어도 `rat-profile --store <path>`를 주면(정상 사용) 갈라짐.

부차 결함 2건:
- **B2 (source_invocation)**: `analysis.py` profile() hit 경로가 `provenance.cache.source_invocation=None` 하드코딩.
  (DESIGN_v2 §9.3 위반. hit=true·새 invocation_id는 정상. 레거시 어댑터 `contracts.py`는 M0에서 이미 정상.)
- **B3 (warm hit ratio 미입증)**: `ab_M2` 하니스가 cold1+warm1 구조라 hit_ratio가 구조적으로 0.5 고정 →
  release gate "warm hit ratio ≥70%"를 입증할 수 없음. (duplicate 3→0 = ≤25% gate는 충족)

## 설계: 단일 루트 해석기 (canonical)

**핵심 결정**: 인덱스 루트를 `--store`/cwd/binary-dir 같은 도구별 우연에 의존하지 말고,
**세 도구가 공유하는 유일 입력(바이너리 내용 해시)**에서 결정론적으로 도출한다.

`bin/ratlib/cache.py`에 단일 해석기 추가 — revq/decomp/rat-profile이 **모두 이것만** 호출:

```python
def resolve_index_root(binary_path, *, override=None) -> str:
    # 1) 명시 override (테스트/파워유저): 인자 or env RAT_INDEX_ROOT
    # 2) ctfguard active lock이 있고 realpath(binary)가 그 solve/<chal>/ 아래면
    #    -> $CTF_HOME/solve/<chal>/.rat        (문제별 자연 통합)
    # 3) fallback (락 없음/범위 밖):
    #    -> $CTF_HOME/.rat-index/<binary_sha256[:16]>/   (해시 앵커, 항상 CTF_HOME 하위=쓰기가능)
```

- 세 도구가 같은 바이너리를 보면 **좌표(cwd/store/바이너리 위치) 무관하게 동일 루트**로 수렴 → sqlite 1개.
- CTF_HOME 하위라 read-only 바이너리 디렉터리 문제도 없음(현 binary-dir 앵커의 잠재 쓰기실패 제거).
- `--store`: 인덱스 배치에서 **제거**(이탈원). rat-profile 아티팩트(profile.json/string-index.json)도
  해석된 루트에 함께 저장(read-through `get(path, root)` 정합 보장). `--store`는 override 별칭으로만 수용(하위호환).

## 작업

### M2R-1 · 해석기 + rat-profile 배선
- **파일**: `bin/ratlib/cache.py` — `resolve_index_root()` 추가.
- **파일**: `bin/ratlib/analysis.py` — `root()`/`_profile_cache_lookup()`/`profile()`가 `resolve_index_root(a.binary, override=a.store)` 사용. 아티팩트 저장 루트도 동일화.
- **Acceptance**: `rat-profile <bin>` 와 `rat-profile <bin> --store /tmp/x` 가 **같은 인덱스 파일**을 쓴다(override 미지정 시). override 지정 시에만 이동.

### M2R-2 · revq/decomp 배선 통일
- **파일**: `bin/revq`, `bin/ratlib/decomp_cache.py` — `dirname(binary)/.rat` 직접 계산 제거, `resolve_index_root()` 호출로 교체.
- **Acceptance**: 동일 바이너리에 대해 revq·decomp·rat-profile이 **동일 sqlite 경로**를 연다(unit).

### M2R-3 · 교차도구 통합 테스트 (누락분 보강 — 재발방지 핵심)
- **파일**: `tests/test_cache.py` — 신규 `test_three_tools_share_one_index`:
  1. 한 바이너리에 revq → decomp → rat-profile 순으로 등록.
  2. **파일시스템에 sqlite가 정확히 1개** 존재(glob `**/indexes/cache.sqlite3`) 단언.
  3. 그 1개 인덱스에서 세 backend(`revq_json`/`decomp_dir`/`profile_artifact`) 엔트리 모두 조회됨.
  4. `dist/` 하위 배치 + `--store` 지정 등 **좌표를 흔들어도** 1개 유지.
- **Acceptance**: 위 테스트가 GREEN. (이게 원결함을 잡았어야 할 테스트)

### M2R-4 · source_invocation 정정 (B2)
- **파일**: `bin/ratlib/analysis.py` — profile() hit 경로가 `cached_doc`의 원 `invocation_id`를
  `provenance.cache.source_invocation`에 기입(레거시 `contracts.py:36-38`와 동형).
  → cached profile 아티팩트에 원 invocation_id가 없다면, 인덱스 엔트리에 `source_invocation`을 함께 저장하도록 `put_entry` 확장 검토.
- **Acceptance**: profile 2회차 hit 문서의 `provenance.cache.source_invocation` == 1회차 invocation_id (unit).

### M2R-5 · warm hit ratio 입증 (B3)
- **파일**: `tests/telemetry/ab_M2.py` — cold pass와 warm pass를 **분리 집계**:
  cold(전량 miss) 세션과 warm(전량 hit) 세션을 각각 측정해 warm 세션의 `cache_hit_ratio`를 기록.
- **Acceptance**: `ab_M2.jsonl`에 warm-run `cache_hit_ratio ≥ 0.70` 실측치 기록(release gate 입증).

### M2R-6 · 회귀 + telemetry 재기록
- **작업**: 컨테이너(`ctf-rat-dev:local`)에서 전체 스위트 + `ab_M2` 재실행, `ab_M2.jsonl` 갱신.
- **Acceptance**: `test_cache`/`test_p2_analysis`/`test_route`… ALL GREEN, warm ratio·duplicate 게이트 동시 충족.

## 완료 게이트
- [ ] `resolve_index_root()` 단일 해석기, 3도구 전부 이것만 호출 (직접 경로계산 0건 — grep으로 확인)
- [ ] `test_three_tools_share_one_index`: 좌표 흔들어도 sqlite 정확히 1개 + 3 backend 조회 (M2R-3)
- [ ] `--store`/cwd/바이너리위치 변화가 인덱스 통합을 깨지 않음
- [ ] profile hit의 `source_invocation` = 원 invocation_id (M2R-4)
- [ ] `ab_M2.jsonl` warm-run hit ratio ≥0.70 실측 (M2R-5) + duplicate ≤25% 유지
- [ ] 마이그레이션: 기존 분산 인덱스가 있어도 재실행 시 새 canonical 루트로 안전 수렴(hit 실패→recompute fallback, 정답성 무영향)

## 롤백
- 해석기는 순수 경로 계산. 인덱스 위치 변경은 hit 실패 시 항상 재실행 fallback이라 **정답성에 영향 없음**(안전).
- env `RAT_INDEX_ROOT`로 구(舊) 동작 강제 가능(feature-flag 성격).

## 하지 말 것
- 새 캐시 파일 포맷 신설 금지(M2 원칙 유지). 3 backend 파일 포맷 불변.
- 인덱스 통합을 핑계로 read-through 규약(§9.4: partial/truncated/stale/version-불일치 미재사용) 완화 금지.
- 이 브랜치에서 macOS `RLIMIT_AS`(runner.py) 같은 M2 외 이슈 혼입 금지 — 별건.
