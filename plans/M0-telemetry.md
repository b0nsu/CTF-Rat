# M0 — 측정 기반 (Telemetry Baseline)

> **왜 먼저인가**: 이후 모든 마일스톤은 "빨라졌다"를 telemetry로 증명해야 다음으로 넘어간다.
> 지금 실측되는 성능값은 tool-result envelope의 `duration_ms` 하나뿐이고, cache_hit/duplicate/
> time_to_flag는 코드·스키마 어디에도 없다. 이 마일스톤이 그 공백을 채운다.

- **브랜치**: `feat/m0-telemetry` (main에서 분기)
- **예상**: 2~3h
- **새 분석 능력**: 0 (계측 배선만)
- **선행**: 없음 (최초 마일스톤)

## 현재 상태 (검증된 사실)
- `bin/ratlib/schema.py:80-85` `benchmark_result()` — `metrics` 키 **존재만** 검증, 내용 측정 안 함.
- A0~A5 ablation은 `schema.py:82` enum 문자열 검증일 뿐 실행 토글 아님.
- 실측값: `duration_ms` (`runner.py:223`, `analysis.py:65`, `contracts.py:42`)의 `rat.tool-result/v1` 일부.

## 작업

### M0-1 · tool-result envelope에 캐시/식별 필드 추가
- **변경**: `rat.tool-result.v1` 스키마에 다음 필드 추가(옵셔널, 하위호환):
  - `tool_name` (str), `params_digest` (sha256 hex), `cache_state` (enum: `hit|miss|bypass`)
- **파일**: `schemas/rat.tool-result.v1.json`, `bin/ratlib/contracts.py`(envelope 생성부), `bin/ratlib/schema.py`(검증부)
- **주의**: `params_digest`는 M2의 canonical key와 **동일 산식**을 쓸 것 — 지금은 필드만 뚫고 값은 placeholder(`"unindexed"`)여도 됨. M2에서 실제 키로 채운다.
- **Acceptance**: 기존 e2e(`tests/e2e_orchestration.py`, `test_p1_contracts.py`) GREEN 유지 + 새 필드가 envelope에 나타남.

### M0-2 · 세션 집계기 `bin/rat-metrics` (read-only)
- **신규 파일**: `bin/rat-metrics` — STATE stream + tool-result envelope들을 읽어 세션 지표 1줄 jsonl 출력.
- **출력 지표(최소)**:
  - `tool_calls` (총), `duplicate_tool_calls` (같은 `params_digest` 2회 이상 재실행 카운트)
  - `cache_hits`, `cache_misses`, `cache_hit_ratio`
  - `time_to_flag_sec` (guard begin → verify PASS 사이 경과; 없으면 null)
  - `functions_decompiled`, `ghidra_runs`, `revq_runs` (envelope tool_name 카운트)
  - `duration_ms_total`
- **제약**: 바이너리 실행 금지, 네트워크 금지, 읽기 전용. 파싱만.
- **파일**: `bin/rat-metrics`, (선택) `bin/ratlib/metrics.py` 헬퍼
- **Acceptance**: rev fixture 1개 세션을 돌린 뒤 `rat-metrics` 실행 → duplicate_tool_calls 정수 출력. 같은 도구 2회 호출 시 카운트 증가 확인.

### M0-3 · baseline 캡처
- **작업**: 현재(슬림화 전) CLAUDE.md + Terra medium 으로 rev fixture 3개 cold 실행 → `rat-metrics` 지표를 `tests/telemetry/baseline_M0.jsonl`에 기록.
- **fixture**: `tests/fixtures/` + `tests/e2e_rev.sh` 활용. angr 미설치 환경이면 최소 2개라도.
- **Acceptance**: `baseline_M0.jsonl`에 fixture별 지표 3줄(또는 가용 개수) 존재. 이 숫자가 이후 A/B의 기준선.

## 설계서 반영 (DESIGN_v2.md — PR1)
- **C1 채택**: `duplicate_tool_calls`는 command 문자열이 아니라 **operation_fingerprint**(tool build+inputs digests+normalized params+deps+policy+output_schema의 sha256) 중복으로 집계. **cache hit은 중복 실행으로 세지 않고 `cache_requests`에만 포함.** M0-2를 이 정의로 고정.
- **C2 채택**: benchmark result v2 필수 필드를 그룹별로 전부 emit — correctness/latency/context/tools/cache/reasoning/artifacts. 단위(ms/bytes/tokens/count) schema 고정. `benchmarks/schemas/rat.benchmark-result.v2.json` 신설(기존 v1은 legacy reference로 보존).
- **C3 예고**: envelope `cache.hit` 필드는 M0-1에서 뚫되, 실제 hit=true 세팅은 M2(hit envelope fix)와 동일 산식으로. M0-1에선 miss 경로 정확 기록 + hit 경로 placeholder 금지(hit 브랜치도 True 반영).
- Acceptance에 "timeout/partial/truncated run은 성공 cache hit로 계산 안 됨"(§7.4) 추가.

## 완료 게이트
- [ ] M0-1 필드 추가(+ hit 브랜치 `cache.hit=true` 보정) + 기존 테스트 GREEN
- [ ] M0-2 `rat-metrics`가 operation_fingerprint 기반 duplicate/cache/ttf 출력
- [ ] `rat.benchmark-result.v2.json` 스키마 + validation 테스트 통과
- [ ] M0-3 baseline jsonl 확보 (컨테이너 `docker/dev`에서, cold/warm 분리)
- [ ] 새 unittest: `tests/test_telemetry.py` (duplicate fingerprint·cold/warm·timeout/partial/truncated accounting)

## 롤백
- 전부 옵셔널 필드 + 신규 파일이라 기존 경로 영향 없음. 브랜치 폐기로 즉시 원복.

## 다음
baseline 숫자 확보 후에만 M1 착수.
