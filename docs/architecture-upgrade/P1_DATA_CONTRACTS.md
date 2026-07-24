# P1 — 공통 schema, artifact store, STATE v2

## 1. 목표와 비목표

### 목표

- 모든 신규 도구 결과를 `rat.tool-result/v1` envelope로 교환한다.
- 원문 출력과 대형 분석 결과를 content-addressed immutable artifact로 저장한다.
- 기존 append-only STATE를 typed event, cursor, invalidation, checkpoint가 있는 v2로 확장한다.
- observation → finding → verified primitive의 수명주기를 기계적으로 검증한다.
- 두 역할이 raw stdout 없이 artifact/finding만으로 같은 문제를 이어받을 수 있게 한다.

### 비목표

- 분석 알고리즘 자체의 정확도 개선(P2 범위).
- 중앙 서버, 원격 object store, 다중 문제 scheduler.
- STATE를 mutable database로 대체하거나 과거 event를 삭제하는 기능.
- artifact 안의 secret 자동 복구. secret은 애초에 저장하지 않는 것이 계약이다.

## 2. 선행조건과 완료 후 보장사항

### 선행조건

- [P0 완료 기준](P0_STABILITY.md#9-완료-기준)을 충족한다.
- P0 runner가 duration, exit, timeout, truncation을 안정적으로 제공한다.
- `run.json`이 `rat.run/v1`의 최소 provenance를 보존한다.
- SHA-256 구현과 atomic write/flock가 지원되는 로컬 filesystem에서 동작한다.

### 완료 후 보장사항

- envelope 하나만 읽어도 결과의 완전성, 실행 provenance, artifact/finding 위치를 판단할 수 있다.
- 동일 byte artifact는 한 번만 저장되고, 기존 object는 덮어쓰거나 수정할 수 없다.
- consumer는 event cursor 이후의 delta만 읽고도 최신 materialized checkpoint를 재구성할 수 있다.
- invalidated evidence를 참조하는 finding/primitive는 자동으로 stale/blocked가 된다.
- STATE v1 challenge를 손실 없이 읽고 v2로 한 번만 migration할 수 있다.

## 3. PDF 백로그 ID 매핑

| ID | 작업 | 구현 결과 |
|---|---|---|
| B008 | tool-result envelope | `rat.tool-result/v1` JSON Schema와 validator |
| B009 | artifact store | `.rat/objects/sha256`, cache index, GC/verify 명령 |
| B010 | STATE v2 | typed append-only events와 v1 importer |
| B011 | delta context | cursor 기반 `state delta`와 context bundle artifact |
| B012 | finding lifecycle | proposed/confirmed/refuted/invalidated/stale 상태 전이 |
| B013 | primitive registry | SELF evidence를 강제하는 verified-only registry |

## 4. 구현 작업 단위와 내부 의존성

```text
B008 schemas ───────┬─ B009 artifact store ── B011 delta context
                    └─ B010 STATE v2 ────────┬─ B012 finding lifecycle
                                             ├─ B013 primitive registry
                                             └─ B011 checkpoints
```

### P1.1 — schema package와 validator

schema는 `additionalProperties: false`를 기본으로 하고, extension은 이름이 있는 `extensions` object 안에서만
허용한다. timestamp는 UTC RFC 3339, digest는 `sha256:<64 lowercase hex>`, ID는 UUIDv7 또는
`<type>_<base32>` 형식으로 고정한다. 모든 document에 `schema` 필드를 둔다.

#### `rat.tool-result/v1` 필수 필드

| 필드 | 형식/의미 |
|---|---|
| `schema` | 고정값 `rat.tool-result/v1` |
| `tool` | `{name, version, build_digest}` |
| `run_id`, `invocation_id` | 실행과 단일 호출의 안정 ID |
| `status` | `ok`, `partial`, `timeout`, `error`, `cancelled` |
| `started_at`, `finished_at`, `duration_ms` | wall time |
| `inputs` | logical role, artifact digest, size 목록 |
| `parameters` | secret 제거 후 canonical option object |
| `summary` | 도구별 작은 typed summary. raw stdout 금지 |
| `artifacts` | `{kind,digest,media_type,size,logical_name}` 목록 |
| `findings` | finding ID와 현재 revision 목록 |
| `diagnostics` | code, severity, message, artifact/locator 목록 |
| `exit` | `{code, signal, timed_out, cancelled}` |
| `provenance` | platform, dependency versions, policy digest, cache `{key,hit,source_invocation}` |

`partial`/`timeout`은 `diagnostics`에 누락 범위와 안전한 continuation/retry 조건을 반드시 포함한다.
`summary`는 32 KiB를 넘길 수 없고 stdout/stderr 전문은 artifact로만 둔다.

#### `rat.run/v1` 필수 필드

| 필드 | 형식/의미 |
|---|---|
| `schema`, `run_id`, `created_at`, `updated_at` | document identity |
| `challenge` | `{id,name,category}`; platform ID가 없으면 local stable ID |
| `status` | `created`, `active`, `blocked`, `verified`, `complete` |
| `inputs` | binary/libc/loader/source/archive의 digest, size, role |
| `target_policy` | guard challenge와 secret 없는 allowlist, network mode |
| `environment` | OS/arch/container, libc/loader provenance, dependency set digest |
| `toolchain` | ctf-rat revision과 schema bundle version |
| `state` | stream ID, latest event cursor, latest checkpoint ID |
| `policy` | resource/context/ROE policy digest |

flag 값, access token, cookie, SSH private key는 schema상 허용하지 않는다. `complete`는 문제 종료 상태이며
`verified` 없이 solve를 뜻하지 않는다.

#### observation 필수 필드 (`rat.observation/v1`)

- `schema`, `observation_id`, `run_id`, `created_at`.
- `producer`: tool/invocation ID.
- `subject`: input digest와 address/symbol/file 같은 locator.
- `kind`: 예를 들어 `elf.protection`, `call.edge`, `register.value`, `memory.marker`, `process.exit`.
- `value`: kind별 schema를 따르는 typed value와 unit/endianness/base.
- `evidence`: 최소 하나의 artifact digest와 byte/line/time/instruction locator.
- `quality`: `direct`, `derived`, `heuristic` 중 하나와 derivation rule.
- `validity`: `active` 또는 `invalidated`, invalidation event ID.

observation의 `quality=heuristic`은 fact로 표시하거나 primitive evidence로 단독 사용할 수 없다.

#### finding 필수 필드 (`rat.finding/v1`)

- `schema`, `finding_id`, `revision`, `run_id`, `created_at`, `updated_at`.
- `title`, `class`, `state`, `confidence`(0~1), `impact`.
- `subject`와 `evidence_observation_ids`(최소 1개; `proposed`만 예외적으로 0개 허용).
- `assumptions`, `contradictions`, `related_findings`.
- `producer_role`, `owner_task_id`.
- `invalidation`: 원인 event/finding/evidence와 reason.

허용 state는 `proposed`, `supported`, `confirmed`, `refuted`, `invalidated`, `stale`다. confidence는 state를
대체하지 않으며 `confirmed`에는 direct evidence가 필요하다.

#### checkpoint 필수 필드 (`rat.checkpoint/v1`)

- `schema`, `checkpoint_id`, `run_id`, `created_at`, `reason`.
- `phase`, `task_id`, `role`, `event_cursor`.
- active observation/finding/primitive ID와 revision.
- `invalidation_cursor`와 반영한 invalidation event ID.
- `context_artifact`: 다음 역할이 읽을 bounded delta bundle digest.
- `budgets`: elapsed/tool-call/token 추정치와 remaining 값.
- `status`: `open`, `handoff`, `converged`, `cancelled`, `terminal`.

### P1.2 — B009 artifact store

```text
<challenge>/.rat/
├── run.json
├── events/
│   └── STATE.v2.jsonl
├── objects/sha256/ab/abcdef...       # immutable bytes
├── metadata/sha256/ab/abcdef....json # media type, size, creation provenance
├── indexes/
│   ├── cache.sqlite3
│   └── refs.sqlite3
├── checkpoints/<checkpoint-id>.json
├── locks/{state,objects,cache}.lock
└── tmp/<invocation-id>/
```

object digest는 **저장되는 정확한 byte sequence**에 대해 SHA-256을 계산한다. text는 생산자가 UTF-8/LF로
canonicalize한 뒤 media type parameter로 이를 선언할 수 있지만 store가 임의 변환하지 않는다. directory는
파일 path, mode의 실행 bit, 개별 digest를 정렬한 canonical manifest JSON을 object로 저장한다.

cache key는 아래 canonical JSON(UTF-8, sorted keys, compact separators)의 SHA-256이다.

```json
{
  "schema": "rat.cache-key/v1",
  "tool": {"name": "...", "version": "...", "build_digest": "sha256:..."},
  "inputs": [{"role": "binary", "digest": "sha256:..."}],
  "parameters": {},
  "dependencies": {},
  "policy_digest": "sha256:...",
  "output_schema": "rat.tool-result/v1"
}
```

timestamp, invocation ID, cwd의 절대경로, terminal 색상은 cache key에서 제외한다. 의미에 영향을 주는 env,
load base, rootfs, libc/loader, timeout·analysis budget은 반드시 parameters/dependencies/policy에 포함한다.

- object는 `O_EXCL` temp write + fsync + digest 재검사 + rename으로 생성한다.
- 같은 digest가 이미 있으면 byte/size를 검증하고 재사용한다. overwrite API는 없다.
- cache index는 mutable해도 object는 immutable하다. index row는 result envelope digest만 가리킨다.
- GC는 `run.json`, event, checkpoint, pinned benchmark에서 reachability를 계산하고 dry-run이 기본이다.

### P1.3 — B010 STATE v2와 migration

STATE v2는 한 줄에 event 하나인 append-only JSONL이다. 공통 필드는 `schema=rat.state-event/v2`,
`stream_id`, 단조 증가 `seq`, `event_id`, `at`, `actor`, `task_id`, `type`, `payload`, `caused_by`다.
flock 아래에서 다음 seq를 배정하고 한 번의 write+fsync로 append한다.

핵심 event type:

- `run.initialized`, `observation.recorded`, `finding.revised`, `primitive.revised`.
- `hypothesis.recorded`, `route.ruled_out`, `next.recorded`, `alert.recorded`.
- `evidence.invalidated`, `checkpoint.created`, `task.started`, `task.cancelled`, `phase.changed`.

cursor는 `{stream_id, seq}`다. consumer는 cursor가 다른 stream이면 fail하고, 보존 범위를 벗어나면 최신
checkpoint부터 다시 materialize한다.

STATE v1 호환:

1. `state show/get`은 v2가 없으면 기존 `STATE.jsonl`을 그대로 읽는다.
2. `state migrate --to-v2 --dry-run`이 모든 v1 줄을 parse하고 mapping report를 낸다.
3. `offset→observation`, `ok→finding(supported)`, `hypothesis→hypothesis`, `primitive→primitive`,
   `no→route.ruled_out`, `alert→alert`, `next/note→동명 typed event`로 변환한다.
4. parse 불가 line은 원문 artifact와 diagnostic event로 보존한다. 조용히 버리지 않는다.
5. 성공하면 v1 digest와 마지막 byte offset을 migration event에 기록한다. 원본은 수정하지 않는다.
6. 같은 digest의 migration은 idempotent하며 새 event를 중복 생성하지 않는다.

### P1.4 — B011 delta context와 checkpoint materialization

`state checkpoint create`는 cursor까지 event를 fold해 checkpoint JSON과 bounded context bundle을 만든다.
bundle에는 새/변경/무효화된 ID, 작은 summary, 필요한 artifact locator만 들어가며 raw stdout은 없다.

```text
state delta --after <cursor> [--until <cursor>] [--role scout] [--max-bytes 32768]
state checkpoint create --phase solve-P2 --task TASK --reason handoff
state checkpoint materialize <checkpoint-id> --verify
```

delta가 한도를 넘으면 중요도 순으로 ID와 summary만 남기고 나머지는 `overflow_artifact`로 연결한다.
`alert`, invalidation, primitive status 변경은 절대 잘라내지 않는다.

### P1.5 — B012 finding lifecycle

허용 전이:

```text
proposed → supported → confirmed
    │           │          │
    └───────────┴──────────► refuted
                └──────────► stale
confirmed ─────────────────► invalidated
stale ──(fresh evidence)───► supported
```

- finding은 수정하지 않고 revision event를 append한다.
- `confirmed`는 active direct observation과 재현 조건이 필요하다.
- evidence invalidation은 dependency graph를 따라 finding을 `invalidated`, 파생 finding을 `stale`로 만든다.
- refuted finding을 같은 근거로 재제안하면 validator가 거부한다. 새 evidence가 있으면 새 revision으로 가능하다.

### P1.6 — B013 primitive registry

primitive document(`rat.primitive/v1`)에는 `primitive_id`, name/class, status(`candidate`, `pass`, `fail`,
`blocked`, `stale`), input/environment digest, SELF 항목별 observation ID, constraints, side effects,
remote-equivalent 여부, producer, revision을 둔다.

- `pass` 승격은 [`PRIMITIVE_GATE.md`](../../doctrine/PRIMITIVE_GATE.md)의 SELF 필수 항목을 schema로 검사한다.
- attacker-controlled marker, register/control target, terminator 영향에 direct evidence가 없으면 거부한다.
- heap primitive는 tcache count/head/order와 해당 시 safe-linking 계산 evidence를 추가 요구한다.
- binary/libc/loader/rootfs digest가 바뀌거나 evidence가 invalidated되면 자동 `stale`이다.
- exploit builder API는 `status=pass`, active evidence, compatible environment인 primitive만 반환한다.

## 5. CLI·schema·파일 레이아웃 변경

```text
rat-artifact put FILE --kind KIND --media-type TYPE
rat-artifact get DIGEST [--output FILE]
rat-artifact verify [DIGEST]
rat-artifact gc --dry-run

state migrate --to-v2 [--dry-run]
state event append --file EVENT.json
state delta --after CURSOR [--until CURSOR] [--max-bytes N]
state checkpoint create|show|materialize ...
state finding propose|support|confirm|refute|invalidate ...
state primitive candidate|pass|fail|block ...
```

repository layout:

```text
schemas/rat.tool-result.v1.json
schemas/rat.run.v1.json
schemas/rat.observation.v1.json
schemas/rat.finding.v1.json
schemas/rat.checkpoint.v1.json
schemas/rat.primitive.v1.json
bin/ratlib/{schema,artifact,state_v2,cache}.py
tests/fixtures/contracts/
```

## 6. 하위 호환성 및 migration

- 기존 `state offset/ok/hypothesis/primitive/no/next/note/alert/show/get` 구문을 유지하고 내부적으로 v2 event를
  쓴다. v1 파일만 있는 디렉터리는 migration 전 read-only 호환 모드다.
- text consumer를 위해 `state show` 기본 출력은 유지하며 `--format json`이 materialized view를 반환한다.
- P0 provisional JSON은 adapter가 `rat.tool-result/v1`로 감싼다. 원문은 stdout artifact로 보존한다.
- schema major version은 자동 변환하지 않는다. reader는 현재와 바로 전 major를 지원하고 unknown major에서
  code 2로 fail한다.
- migration은 dry-run report, backup digest, idempotency test 없이는 write하지 않는다.

## 7. 실패 모드와 보안 조건

| 실패 모드 | 요구 동작 |
|---|---|
| invalid envelope/event | quarantine artifact 저장, STATE/materialized view에 merge 금지 |
| object digest mismatch | cache miss가 아니라 corruption; object 격리 후 run blocked |
| append 중 partial line | 마지막 valid cursor까지만 읽고 repair report 생성 |
| concurrent writer | flock와 seq compare; 중복 seq 거부 |
| stale cache index | envelope/object digest 검증 후 miss 처리 |
| invalidated evidence | 의존 finding/primitive stale 또는 invalidated, exploit 입력 차단 |
| oversized summary/delta | bounded summary + overflow artifact, alert/invalidation 보존 |
| secret 발견 | 저장 전 redaction 또는 전체 거부; digest/logical name에도 secret 금지 |
| v1 parse 실패 | 원문 보존 diagnostic, migration success로 보고 금지 |

artifact logical name은 UI 힌트일 뿐 경로로 사용하지 않는다. object retrieval은 digest만 받으며 path traversal을
허용하지 않는다. cache hit도 현재 ROE/target policy 검사를 우회하지 못한다.

## 8. 테스트 fixture와 실행 명령

필수 fixture:

- 모든 schema의 최소 valid, unknown field, wrong enum, oversized summary, invalid digest.
- 동일 bytes/different name dedup, hash mismatch, concurrent put, interrupted write, stale cache row.
- STATE v1의 모든 event 종류, malformed line, duplicate migration, concurrent v2 append.
- finding 정상/불법 전이, evidence invalidation cascade, environment 변경 primitive stale.
- cursor delta의 empty/overflow/wrong stream/compacted checkpoint case.
- stdout 10 MiB를 내는 producer와 raw stdout을 전혀 읽지 않는 consumer 역할.

구현 후 실행 명령:

```sh
python3 -m unittest tests.test_schemas tests.test_artifact_store tests.test_state_v2
python3 -m unittest tests.test_finding_lifecycle tests.test_primitive_registry
python3 tests/e2e_artifact_handoff.py
bin/pkselftest --strict-optional
```

`e2e_artifact_handoff.py`는 역할 A가 tool 실행 후 envelope/artifact/finding ID만 남기고 종료한 다음, 역할 B가
stdout 파일과 A의 대화 내용에 접근하지 않은 상태에서 checkpoint를 읽어 동일 finding을 검증해야 한다.

## 9. 완료 기준

- [ ] 여섯 schema가 versioned fixture와 함께 validation된다.
- [ ] 모든 신규 결과가 valid `rat.tool-result/v1`이며 summary에 raw stdout이 없다.
- [ ] object put/get/verify가 byte digest를 보존하고 immutable overwrite를 거부한다.
- [ ] cache key가 content/tool/dependency/policy 변화에 따라 정확히 invalidation된다.
- [ ] STATE v1 읽기와 dry-run/v2 migration이 손실·중복 없이 동작한다.
- [ ] cursor delta와 checkpoint materialization이 같은 active view를 만든다.
- [ ] invalidation cascade가 finding과 primitive를 stale/blocked로 만든다.
- [ ] primitive PASS가 SELF evidence 누락 또는 환경 불일치에서 거부된다.
- [ ] **두 역할이 raw stdout 없이 artifact/finding만으로 인계하는 e2e가 통과한다.**
- [ ] 기존 `state` 텍스트 CLI와 P0 selftest가 회귀하지 않는다.

## 10. 권장 커밋 분할

1. `feat: define versioned rat data schemas`
2. `feat: add immutable content-addressed artifact store`
3. `feat: add typed STATE v2 events and v1 reader`
4. `feat: migrate legacy state with idempotent reports`
5. `feat: materialize cursor checkpoints and delta context`
6. `feat: enforce finding lifecycle and invalidation`
7. `feat: register SELF-verified primitives only`
8. `test: prove artifact-only role handoff`

## 11. 진행 체크리스트

- [x] B008 envelope/schema (legacy tool adapters included)
- [x] B009 artifact store/cache index
- [x] B010 STATE v2/migration
- [x] B011 delta/checkpoint
- [x] B012 finding lifecycle
- [x] B013 primitive registry
- [x] artifact-only handoff e2e
- [x] [완료 기준](#9-완료-기준) 전체 확인
