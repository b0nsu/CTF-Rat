# P4 — benchmark, KPI, calibration

## 1. 목표와 비목표

### 목표

- pwn/rev 40개 executable corpus와 중간 단계 ground truth를 동결한다.
- solve 여부뿐 아니라 속도, 비용, 중복, cache, evidence, 오판, triage recall을 계산 가능하게 수집한다.
- PDF의 A0~A5 비교 실험으로 데이터 계약, 분석 도구, fan-out, context governor, skeptic 효과를 분리한다.
- nightly regression이 기능·정확도·성능 하락을 재현 가능한 규칙으로 차단한다.
- 백로그 PDF의 목표 수치를 v1 승인 기준으로 정확히 전사하고 변경 이력을 남긴다.

### 비목표

- public leaderboard나 다른 팀과의 순위 비교.
- benchmark flag 자동 제출, 원격 서비스 부하 시험, 문제 간 자동 queue.
- corpus 결과에 맞춘 수동 예외를 production 코드에 넣는 것.
- 한 번의 noisy run만으로 threshold를 자동 완화하는 것.

## 2. 선행조건과 완료 후 보장사항

### 선행조건

- [P3 완료 기준](P3_MULTI_AGENT.md#9-완료-기준)을 충족한다.
- 기준 PDF SHA-256 `41244dff6a95bfb6269249b180497dfe745f21bb3b6c4bcadb2b7d250e0f9b95`와
  인쇄 페이지 30~31의 corpus/KPI/비교 실험 표를 기준으로 사용한다.
- 동일 machine class 또는 기록된 container/CPU 정책에서 A0~A5를 실행할 수 있다.
- corpus 사용권과 재배포 조건을 검토하고 secret/실대회 credential이 제거돼 있다.

### 완료 후 보장사항

- 결과 JSONL만으로 모든 KPI를 다시 계산할 수 있다.
- 각 solve가 어느 intermediate ground truth와 executable oracle로 검증됐는지 추적할 수 있다.
- 동일 corpus/input/budget에서 아키텍처 변형 간 paired comparison이 가능하다.
- PDF v1 목표와 상대 regression guardrail 중 하나라도 위반하면 승인되지 않는다.
- threshold 변경은 소급 수정이 아니라 새 version으로만 이뤄진다.

## 3. PDF 백로그 ID 매핑

| ID | 작업 | 구현 결과 |
|---|---|---|
| B027 | 40개 corpus | category/난이도 균형, executable oracle, intermediate truth manifest |
| B028 | KPI collector | event/envelope에서 PDF의 12개 KPI를 재계산하는 collector |
| B029 | A0~A5 ablation | single/multi/tool/context/verify variant의 paired result |
| B030 | nightly regression | baseline lock, threshold 판정, trend/report artifact |

## 4. 구현 작업 단위와 내부 의존성

```text
B027 corpus + PDF baseline freeze
        ├────────► B028 KPI collector
        │                 │
        └────────► B029 A0~A5 ablation
                          │
                          └────────► B030 nightly regression
```

### P4.1 — B027 40개 corpus

> **현재 상태 감사 (2026-07-22): B027은 완료가 아니다.** `benchmarks/corpus/v1`의 40개 항목은
> corpus 배포/collector 배관을 시험하는 synthetic smoke fixture다. 모든 manifest가 `CC0-1.0 synthetic fixture`와
> `src/fixture.py`를 가리키고, source/binary/container digest는 placeholder이며, fixture와 checker도 각각 한 종류의
> 동일한 프로그램이다. 입력 `solve:<challenge-id>`를 그대로 `verified:<challenge-id>`로 바꾸는 것을 제외한
> pwn/rev 동작, 실제 binary, intermediate truth가 없다. 그러므로 이들은 **release corpus 분모, A0~A5 성능 주장,
> PDF B027 완료 근거로 사용할 수 없다**. 상세 증거와 실제 자산 ingestion 순서는
> [P4_CORPUS_INGESTION.md](P4_CORPUS_INGESTION.md)에 고정한다.

v1은 pwn 18개, rev 17개, regression fixture 5개로 고정한다. 한 challenge가 여러 기술을 포함해도 primary category는 하나만 지정해
분모 중복을 막고 secondary tags를 별도로 둔다.

| 영역 | primary category | 개수 | 필수 중간 ground truth |
|---|---|---:|---|
| pwn | stack/format | 7 | ret2win/ret2libc/partial overwrite/format read-write/stack pivot ground truth |
| pwn | heap/allocator | 6 | libc/loader digest, allocation timeline, bin state, corruption primitive |
| pwn | advanced | 5 | seccomp/ORW, static, Rust, stateful protocol, kernel ground truth |
| rev | native | 6 | stripped/arithmetic/crypto/C++/Rust/Go validation path와 executable oracle |
| rev | VM/obfuscation | 6 | stack/register VM, opcode shuffle, flattening, runtime decode semantics |
| rev | platform | 5 | PE/DLL, .NET/PyInstaller, ARM/firmware, Node addon runtime ground truth |
| regression | malformed/tooling | 5 | malformed input, archive, cache, timeout, partial-analysis expected behavior |
| 합계 |  | **40** |  |

난이도는 easy 14, medium 16, hard 10으로 고정하며 각 영역에 최소 하나의 timeout/partial 경로를 포함한다.
최소 8개는 plausible false-positive signal, 6개는 환경/libc/rootfs mismatch, 4개는 terminator 또는 short I/O 함정을
포함해 skeptic과 evidence gate를 측정한다.

corpus manifest에는 stratified `calibration` 24개와 `holdout` 16개 split을 고정한다. heuristic score, route
threshold, timeout budget 조정은 calibration split에서만 수행한다. holdout ground truth는 evaluator만 읽고,
승인 report는 전체 40개와 holdout 값을 함께 보여 준다. challenge를 split 사이에서 옮기면 corpus major version을
올린다.

각 `challenge.yaml` 필수 필드:

- schema, corpus/challenge ID, version, license/source, redistributable 여부.
- category, secondary tags, difficulty, supported architectures.
- source/build recipe와 source digest, compiler/container digest, stripped/protection options.
- binary/libc/loader/rootfs artifact digest와 deterministic scenario.
- expected fact/signal/top route, vulnerable/validation location, required finding/primitive.
- intermediate ground truth observation과 허용 locator tolerance.
- success/failure executable oracle, expected exit/output effect. flag 본문은 필요하지 않다.
- per-stage wall/tool-call/token budget과 deterministic seed.
- unsupported backend와 skip이 허용되는 정확한 조건.

corpus는 source-build fixture를 우선한다. public challenge를 포함할 때 license상 binary 재배포가 불가능하면 fetch
script와 upstream digest만 추적하고 nightly secret/credential에 의존하지 않는다.

### PDF v1 목표 동결

기준은 PDF 인쇄 페이지 30~31의 17.2 표다. 다음 값을 `pdf-v1.yaml`에 그대로 전사하고, source locator가
없으면 benchmark runner가 시작을 거부한다.

```yaml
schema: rat.benchmark-thresholds/v1
baseline_id: pdf-v1
source:
  sha256: "sha256:41244dff6a95bfb6269249b180497dfe745f21bb3b6c4bcadb2b7d250e0f9b95"
  document: "CTF-Rat_bin_architecture_upgrade_report_ko_corrected.pdf"
targets:
  verified_solve_at_1: {relative_min: 0.15, baseline: A0, source: "printed p.30 §17.2"}
  median_tts_easy_medium: {relative_max: -0.25, source: "printed p.30 §17.2"}
  first_primitive_time: {relative_max: -0.30, source: "printed p.30 §17.2"}
  tokens_per_verified_solve: {relative_max: -0.25, source: "printed p.30 §17.2"}
  strong_model_token_share: {max: 0.45, source: "printed p.30 §17.2"}
  duplicate_call_rate: {max: 0.05, source: "printed p.30 §17.2"}
  cache_hit_rate: {min: 0.60, source: "printed p.30 §17.2"}
  evidence_coverage: {min: 0.95, source: "printed p.30 §17.2"}
  false_solve_rate: {max: 0.00, source: "printed p.30 §17.2"}
  top3_recall: {min: 0.85, source: "printed p.30 §17.2"}
  exploit_reliability: {local_min: 0.95, remote_min: 0.85, source: "printed p.31 §17.2"}
  context_compression_ratio: {min: 10.0, source: "printed p.31 §17.2"}
```

실제 `benchmarks/baselines/pdf-v1.yaml`에는 위 값과 비교 방향이 모두 있어야 한다. review 시 두 사람이 PDF와 대조하고 transcript에 서명한다. 이 파일이 동결된
뒤 **그 PDF 목표 수치가 v1 승인 기준**이다.

### P4.2 — B028 KPI collector

측정 단위는 `(benchmark_run_id, ablation_id, challenge_id, attempt=1)`이다. warm-up과 infra retry는 별도
event이며 attempt를 덮어쓰지 않는다. KPI 정의:

| KPI | 계산식/정의 |
|---|---|
| **Verified Solve@1** | 첫 전체 run에서 공통 외부 reliability oracle과 variant가 지원하는 내부 gate를 통과한 challenge 수 / eligible challenge 수 |
| **TTS** | `run.started_at`부터 verified terminal checkpoint까지 wall seconds. 미해결은 budget에서 right-censored하며 solved subset 평균만으로 숨기지 않음 |
| **first primitive** | run 시작부터 첫 compatible primitive가 PASS가 된 event까지 seconds. 없으면 censored |
| **token** | 모든 role의 reported input+output token 합. 미제공 transport는 byte/4 추정치를 별도 flag와 함께 합산 |
| **strong-model token share** | strong reasoning model의 input+output token / 전체 model token |
| **duplicate call** | 같은 run에서 동일 cache key를 cache hit 없이 두 번째 이상 실제 실행한 호출 수 / cacheable invocation 수 |
| **cache hit** | valid cache envelope을 사용한 lookup 수 / 전체 cacheable lookup 수. cold와 warm run을 분리 |
| **evidence coverage** | ground truth가 요구한 claim 중 active direct observation locator로 연결되고 validator를 통과한 claim 수 / required claim 수 |
| **false solve** | verified/solve로 선언했으나 oracle, skeptic 재검증, provenance 중 하나에서 실패한 선언 수 / 전체 solve 선언 수. 선언 0이면 0이 아니라 N/A |
| **top-3 recall** | profile/triage의 첫 ranking top 3에 ground-truth primary vuln/validation location이 포함된 eligible challenge 수 / eligible challenge 수 |
| **exploit reliability** | 동일 exploit의 독립 반복 성공 수 / 전체 실행 수. local과 remote-equivalent를 분리 |
| **context compression** | agent에게 전달하지 않고 artifact에 보존한 raw text bytes / 실제 agent context bytes |

중복 호출은 tool name이 아니라 P1 cache key로 판단한다. evidence coverage는 단순 artifact 존재가 아니라 정확한
observation locator와 validity를 검사한다. category별 micro 값과 challenge 동일 가중 macro 값을 모두 보고한다.
TTS/first primitive는 median, p75, p90과 Kaplan-Meier curve를 저장한다.

calibration report는 signal confidence의 reliability bin, Brier score, top-3 recall을 category별로 추가 기록한다.
confidence를 올리는 방향으로만 threshold를 맞추지 않고 false-positive/false-solve cost를 함께 계산한다. nightly
holdout 결과를 보고 heuristic threshold를 직접 튜닝하는 행위는 금지하며, 변경은 다음 corpus version의
calibration split에서 검증한다.

### P4.3 — B029 A0~A5 ablation

모든 ablation은 같은 corpus version, seed, budget, machine class, model/agent version을 사용한다.

| ID | 활성 구성 | 측정 의도 |
|---|---|---|
| A0 | 현재 단일 agent + 기존 `/bin` | 현재 baseline |
| A1 | 단일 agent + STATE v2/artifact | 데이터 계약만으로 시간/token이 줄어드는지 측정 |
| A2 | A1 + slice/dyn/verify | 분석 정확도와 false solve 개선 측정 |
| A3 | A2 + solve-P2 multi-agent | fan-out의 solve/time 이득 측정 |
| A4 | A3 - context governor | context 제어가 없을 때 비용 증가 측정 |
| A5 | A3 - skeptic/verify | 검증 계층이 막는 false solve 측정 |

A0/A1은 독립 benchmark oracle을 공통 외부 판정기로 사용한다. A4/A5는 A3의 구성요소를 하나씩 제거하는
비누적 ablation이므로 A5를 최종 production 구성으로 해석하지 않는다. production candidate는 A3다.

각 challenge를 cold cache로 최소 3회 실행하고, artifact/cache 효과를 보는 A1~A5는 동일 입력의 warm run을 별도 1회
실행한다. 순서는 seeded Latin-square로 섞어 thermal/order bias를 줄인다. infra failure는 결과를 삭제하지 않고
분류하며, 최대 1회 재시도도 원 attempt와 함께 보존한다.

### P4.4 — B030 nightly regression

baseline freeze 조건:

- corpus manifest digest, PDF threshold digest, ctf-rat commit, schema bundle, toolchain/container, model/agent ID,
  resource/context policy, seed set을 하나의 `baseline.lock.json`에 기록한다.
- merge-base의 최근 승인 A3 결과를 production performance baseline으로 사용한다. 같은 환경 digest가 아니면 절대값 PDF
  gate만 판정하고 상대 비교는 `not-comparable`로 표시한다.
- benchmark 결과를 수정하지 않는다. 재실행은 새 run ID다.

성능 하락 판정:

1. false solve > PDF 허용값, schema-invalid merge, oracle bypass, corpus 누락은 즉시 hard fail이다.
2. 각 KPI가 `pdf-v1.yaml`의 min/max 목표를 위반하면 v1 승인 실패다.
3. 비교 가능한 paired run에서 lower-is-better(TTS, first primitive, token, duplicate call)는 paired median이
   baseline보다 10% 넘게 악화되고 bootstrap 95% CI 하한도 0을 넘으면 regression이다.
4. higher-is-better(Solve@1, cache hit, evidence coverage, top-3 recall)는 5 percentage point 이상 하락하고
   bootstrap 95% CI 상한도 0 미만이면 regression이다.
5. 전체 macro가 통과해도 primary category 하나가 10 percentage point 이상 하락하면 category regression으로
   fail한다. 단일 flaky challenge는 quarantine할 수 있지만 분모에서 조용히 빼지 않는다.

10%/5pp는 PDF 목표를 대체하지 않는 nightly 상대 guardrail이다. threshold 변경 절차:

1. `benchmark-threshold-change` RFC에 old/new 값, PDF 또는 새 근거, 원인, 최근 10회 재계산, category 영향을 적는다.
2. corpus/code 변경과 threshold 완화를 같은 커밋에서 하지 않는다.
3. 두 reviewer가 승인하고 baseline ID를 새 major/minor로 올린다. 기존 result에는 이전 threshold를 유지한다.
4. noisy run 때문에 자동으로 threshold를 조정하거나 failed nightly를 새 baseline으로 승격하지 않는다.

## 5. CLI·schema·파일 레이아웃 변경

```text
rat-bench validate-corpus [--version v1]
rat-bench run --ablation A0..A5 --seed N --cache cold|warm
rat-bench collect ONE_RUN_RESULT_DIR --baseline benchmarks/baselines/pdf-v1.yaml [--reference A0_METRICS.json]
rat-bench compare --candidate RUN --baseline RUN
rat-bench nightly --lock benchmarks/baselines/baseline.lock.json --candidate A3_CANDIDATE.json --baseline APPROVED_A3.json --reference A0_REFERENCE.json
```

```text
benchmarks/
├── corpus/v1/<challenge-id>/{challenge.yaml,src/,build/,oracle/}
├── baselines/{pdf-v1.yaml,pdf-v1.transcript.json,baseline.lock.json}
├── ablations/A0.yaml ... A5.yaml
└── schemas/
    ├── rat.benchmark-challenge.v1.json
    ├── rat.benchmark-event.v1.json
    ├── rat.benchmark-result.v1.json
    └── rat.benchmark-thresholds.v1.json

.rat-bench/<benchmark-run-id>/
├── run.json
├── events.jsonl
├── challenge-results.jsonl
├── metrics.json
├── report.md
└── artifacts.json
```

`events.jsonl`은 append-only 원자료, `challenge-results.jsonl`은 challenge/attempt 집계, `metrics.json`은 재계산
가능한 aggregate다. CI는 `.rat-bench` 전문을 git에 넣지 않고 digest가 있는 artifact로 보존한다.

## 6. 하위 호환성 및 migration

- 기존 e2e/selftest는 A0와 corpus smoke subset의 source로 재사용하되 KPI ground truth manifest를 추가한다.
- 과거 수동 solve 기록은 schema/provenance가 없으므로 공식 baseline 분모에 자동 포함하지 않는다.
- corpus version을 바꾸면 v1 결과와 직접 합치지 않는다. mapping report와 overlap subset 비교를 제공한다.
- metric 정의 변경은 schema/metric version을 올리고 과거 raw events를 새 정의로 재계산하되 원 metrics를 보존한다.
- dependency가 없는 platform의 skip은 manifest가 허용한 경우만 eligible 분모에서 제외하고 skip count를 항상 표시한다.

## 7. 실패 모드와 보안 조건

| 실패 모드 | 요구 동작 |
|---|---|
| PDF 값/locator 누락 | runner 시작 거부; 0/임의값으로 승인 금지 |
| corpus digest drift | baseline incomparable, 새 corpus version 요구 |
| oracle가 solver에 노출 | run 무효; oracle capability/process 분리 |
| flaky/non-deterministic fixture | 결과 보존 후 quarantine, 분모 변화 명시 |
| infra timeout/OOM | solve failure와 별도 infra failure, 재시도 연결 |
| missing event/token | 해당 KPI unknown; 0으로 대체 금지 |
| false solve | hard fail 및 evidence/invalidation trace 보존 |
| warm cache contamination | cold run 무효, fresh store에서 재실행 |
| remote target 사용 | corpus에서 금지; local/container executable oracle만 |
| embedded real flag/secret | fixture 거부 또는 synthetic token으로 교체 |

benchmark agent에는 oracle source와 expected flag를 보여주지 않는다. collector만 read-only oracle 결과를 받는다.
모든 fixture 실행은 P0 sandbox/resource/network-none 정책을 쓴다.

## 8. 테스트 fixture와 실행 명령

collector unit fixture는 solve/pass/fail/censored/unknown, duplicate cache key, stale hit, invalid evidence, false solve,
top-3 tie, category skip을 포함한다. 현재 `benchmarks/corpus/v1`은 이 수준의 **fixture smoke corpus**이며,
category당 최소 1개(총 7개)만 실행한다. fixture smoke의 성공은 runner/collector/oracle wiring만 뜻한다.
실제 release corpus가 ingest된 뒤에만 nightly shard가 40개 전체 executable challenge를 실행한다.

구현 후 실행 명령:

```sh
python3 -m unittest tests.test_benchmark_manifest tests.test_kpi_collector
python3 -m unittest tests.test_ablation_matrix tests.test_regression_gate
rat-bench validate-corpus --version v1
rat-bench run --ablation A0 --seed 1 --cache cold --subset smoke
rat-bench run --ablation A3 --seed 1 --cache cold --subset smoke
rat-bench collect .rat-bench/<one-run> --baseline benchmarks/baselines/pdf-v1.yaml --reference A0_METRICS.json
rat-bench nightly --lock benchmarks/baselines/baseline.lock.json --dry-run
```

release candidate에서는 A0~A5 × cold 3 seed와 A1~A5 × warm 1 seed를 40개 전체에 실행한다.

## 9. 완료 기준

- [ ] 40개 **실제 executable CTF challenge**가 표의 category/난이도 합계와 executable oracle 요구를 만족한다. synthetic smoke fixture는 이 분모에 넣지 않는다.
- [ ] 모든 실제 challenge에 fact→finding→primitive/solution의 중간 ground truth가 있다. truth는 benchmark agent가 읽을 수 없는 evaluator capability로 보관한다.
- [ ] PDF SHA-256과 page/table/cell 근거가 있는 `pdf-v1.yaml`이 동결되고 두 사람이 대조했다.
- [ ] PDF의 12개 KPI가 raw event/result에서 결정론적으로 재계산된다.
- [ ] censored/unknown/skip/infra failure가 0이나 solve failure로 왜곡되지 않는다.
- [ ] A0~A5가 동일 corpus/seed/budget에서 실행되고 component matrix와 일치한다.
- [ ] cold/warm cache와 candidate/verified solve가 분리된다.
- [ ] nightly가 PDF 목표, false solve hard gate, 상대/category regression을 판정한다.
- [ ] threshold 변경이 versioned RFC와 새 baseline 없이 불가능하다.
- [ ] 전체 result 형식과 artifact digest가 CI에서 보존되고 report를 재생성할 수 있다.

## 10. 권장 커밋 분할

1. `test: define versioned 40-challenge benchmark corpus`
2. `chore: freeze pdf v1 targets with source transcript`
3. `feat: collect reproducible solve and evidence metrics`
4. `feat: define A0 through A5 ablation matrix`
5. `feat: compare paired benchmark runs and censored timing`
6. `ci: run nightly corpus regression gates`
7. `docs: document threshold review and baseline promotion`

## 11. 진행 체크리스트

- [ ] B027 real corpus/ground truth ingestion (현재 것은 distribution-valid synthetic smoke fixture뿐)
- [ ] PDF v1 baseline transcription/freeze
- [x] B028 KPI collector
- [x] B029 A0~A5 ablation matrix
- [x] B030 nightly threshold/relative regression gates
- [ ] full-corpus release candidate run
- [ ] [완료 기준](#9-완료-기준) 전체 확인
