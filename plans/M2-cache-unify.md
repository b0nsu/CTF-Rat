# M2 — 통합 캐시 read-through 인덱스

> **왜**: 캐시가 3세계로 파편화(ratlib sqlite / decomp json / revq json), 통합 인덱스 0.
> 그래서 같은 strings/decomp/revq를 재실행 → 컨텍스트·시간 낭비. **새 캐시를 만들지 않고**
> 기존 `ratlib.cache` sqlite를 canonical read-through 조회 계층으로 승격, 3개 캐시 파일은 그대로 두되
> 인덱스 하나가 셋을 가리키게 한다.

- **브랜치**: `feat/m2-cache-unify` (main에서 분기)
- **예상**: 반나절
- **새 분석 능력**: 0 (캐시 배선만)
- **선행**: M1 완료 (context↓ 증명), M0-1의 `params_digest` 필드

## 현재 상태 (검증된 사실)
- `bin/ratlib/cache.py` — sqlite `<root>/indexes/cache.sqlite3`, `cache(key TEXT PK, envelope_digest TEXT)` 2컬럼. key=tool/inputs/params/deps/policy/schema의 canonical JSON SHA256. 소비자는 `contracts.py:28-29`뿐, tool_version 하드코딩 `"legacy-adapter/v1"`.
- `bin/ratlib/decomp_cache.py` — `<bin>.decomp/.rat-cache.json`, key=binary_sha256+ghidra_version+script hash+analyzer_options.
- `bin/revq` — `<bin>.revq.json`, 유효성=sha256/schema/engine 필드 매칭. tool_version 개념 없음.

## 설계: canonical key
```
key = sha256(canonical_json({
  "binary_sha256": <bin hash>,
  "tool_name":     "revq" | "decomp" | "rat-profile" | ...,
  "tool_version":  <실제 버전/build digest>,   # 하드코딩 문자열 제거
  "params":        <정규화된 인자>,
  "dep_versions":  {angr, ghidra, binutils, ...},
}))
```
- sqlite 인덱스 row: `key → {backend, path, produced_at, envelope_digest}` (backend ∈ revq_json|decomp_dir|profile_artifact).
- **read-through 규약**: 도구는 실행 전 key 조회 → hit면 해당 backend 파일 재사용(+`cache_state:hit` emit) → miss면 실행·파일 생성 후 인덱스 등록(+`cache_state:miss`).
- **불변조건**: 잘리거나 실패한 결과는 등록 금지(기존 legacy adapter 규약 유지).

## 작업

### M2-1 · canonical key 헬퍼
- **파일**: `bin/ratlib/cache.py` — `canonical_key(binary_sha256, tool_name, tool_version, params, dep_versions)` 추가. 하드코딩 `"legacy-adapter/v1"` 제거하고 실제 tool_version 주입.
- **인덱스 스키마 확장**: `cache(key PK, backend TEXT, path TEXT, produced_at TEXT, envelope_digest TEXT)` (마이그레이션: 기존 2컬럼 → ALTER/재생성, 하위호환 read).
- **Acceptance**: `tests/test_cache.py` — 동일입력=동일키, tool_version 변경 시 miss, params 순서 무관(canonical).

### M2-2 · revq 인덱스 연결
- **변경**: `bin/revq` `load_or_extract`가 실행 전 canonical_key로 sqlite 조회 → hit면 `<bin>.revq.json` 재사용, miss면 추출 후 인덱스 등록. `cache_state` emit.
- **Acceptance**: 같은 바이너리에 revq 2회 → 2회차 `cache_state:hit`, `rat-metrics` duplicate 미증가.

### M2-3 · decomp 인덱스 연결
- **변경**: `bin/decomp`/`decomp_cache.py` — 이미 provenance key 있음 → 그 key를 canonical 인덱스에 등록/조회만 추가(중복 계산 방지).
- **Acceptance**: decomp 재호출 시 hit, Ghidra 재실행 안 함.

### M2-4 · rat-profile 인덱스 연결
- **변경**: `bin/rat-profile` — profile.json/string-index 아티팩트 digest를 canonical 인덱스에 등록/조회.
- **Acceptance**: profile 재호출 hit.

### M2-5 · 통합 검증
- **작업**: M0 baseline과 동일 fixture 재실행 → `rat-metrics`로 `duplicate_tool_calls`·`cache_hit_ratio` 비교, `tests/telemetry/ab_M2.jsonl` 기록.
- **Acceptance**: duplicate_tool_calls가 M0 대비 감소, cache_hit_ratio 상승 증거.

## 완료 게이트
- [ ] canonical_key + 인덱스 스키마 + `tests/test_cache.py`
- [ ] revq/decomp/rat-profile 3도구 read-through 연결
- [ ] cache_state가 tool-result envelope에 정확 기록(M0-1 필드 채움)
- [ ] M2-5에서 duplicate↓ 증명

## 롤백
- 인덱스 스키마 변경은 마이그레이션 함수로 원복 가능. 도구별 조회는 hit 실패 시 항상 재실행 fallback이라 **캐시 손상이 정답성에 영향 주지 않음**(안전).

## 하지 말 것
- 새 캐시 파일 포맷 신설 금지. 3개 backend 파일은 그대로. 인덱스만 추가.
