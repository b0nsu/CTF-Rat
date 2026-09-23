# CTF-Rat v2.1 풀이 지원 기능 PRD

| 항목 | 내용 |
|---|---|
| 상태 | 기능 구현·검증 완료 — 성능 효과는 미측정 |
| 작성일 | 2026-09-23 |
| 검토 기준 | 로컬 `dev` @ `ec90774f5f322030641767ef79a87fb72344a968` |
| 대상 사용자 | CTF-Rat으로 인가된 Pwn·Reverse 문제를 분석하는 에이전트와 작업자 |
| 구현 순서 | Pattern Retrieval → Governor 개선 → 지속형 GDB |
| 검증 범위 | 기능·실패 경로·기존 계약 회귀 검증 |
| 제외 | 신규 성능 계측, A0 확보, A/B·ablation 실험, 해결률 개선 입증 |

## 1. 배경과 문제

현재 CTF-Rat은 non-ranking Router v2, bounded query, 지연 Skill 로드,
Artifact Store, typed STATE 및 완료 검증 경계를 갖고 있다. 이번 작업은
이 구조를 유지하면서 다음 세 가지 사용상의 공백을 보완한다.

1. 정적 lead만 얻은 시점에는 관련 기법의 필요조건·반증 조건·다음 실험을
   작은 출력으로 조회하는 전용 경로가 없다.
2. Governor의 진전 이벤트에 가설·미확인 사항·다음 행동 메모가 포함되어,
   새로운 분석 증거 없이도 진행 중으로 처리될 수 있다.
3. 현재 동적 분석의 GDB 경로는 배치 실행이며, 같은 프로세스에서 여러 단계의
   관측을 이어가는 세션 기능이 없다.

원안은 `CTF-Rat_v2.1_Solve_Capability_Upgrade_Research_Design_Plan.md`
(2026-09-21, 기준 커밋 `d2c239a`)이다. 이 PRD는 사용자 요청에 따라 원안의
계측 선행 및 비교 실험 요구를 이번 범위에서 제외한다. 원안 전체의 완료를
선언하는 문서가 아니다.

## 2. 목표와 성공 정의

### 목표

- Skill 확정 전에도 기존 지식에서 가설 검토에 필요한 부분을 좁혀 조회한다.
- 단순 메모 변경과 실제 분석 증거의 갱신을 구분한다.
- 필요한 경우 같은 디버깅 프로세스에서 연속 관측을 수행한다.
- 후보 지식·관측을 기존 PASS/SOLVED 증거와 명확히 구분한다.

### 성공 정의

기능별 수용 기준과 필수 회귀 검증을 충족하면 구현 완료로 판단한다.
해결률 상승, 토큰 절감, 풀이 시간 감소는 이번 작업에서 측정하지 않으며
미검증으로 명시한다. 기능 테스트 통과를 성능 개선의 증거로 사용하지 않는다.

### 비목표

- A0 실행 래퍼 보수 및 정상 baseline 확보
- 신규 사용량·지연·토큰·캐시 계측과 대시보드
- A0/A1/A2/A3 비교 또는 실제 에이전트 대규모 벤치마크
- MCP·ReVa·Web·CTFd·Dreamhack 연결
- 새 상태 DB, 벡터 DB, 독립 실행 엔진, 중복 캐시
- 외부 Skill·war-story·소스 코드의 복사 또는 벤더링
- 자동 exploit 전략 확정, 자동 fan-out, 검증 기준 완화

기존 계측은 제거하지 않는다. 증거 출처, digest, 실행 identity, 관측 순서,
오류·잘림 상태 기록은 무결성과 재현을 위한 기능 요구이며 생략하지 않는다.

## 3. 사용자 시나리오

| ID | 상황 | 기대 동작 |
|---|---|---|
| US-01 | heap와 format lead가 함께 관측됨 | 관련 후보 카드를 제한된 출력으로 읽고 전제·반증 실험을 비교한다. 단일 취약점으로 확정하지 않는다. |
| US-02 | 새 가설 메모만 남기며 같은 조회를 반복함 | Governor는 메모 추가만으로 stuck을 해제하지 않는다. |
| US-03 | 새 관측이 기존 가설을 반증함 | 유효한 증거 변경을 진전으로 인식하고 다음 판단 근거를 제공한다. |
| US-04 | heap 객체의 수명을 여러 breakpoint에서 확인함 | 같은 프로세스에서 연속 관측하고 세션·실행 조건을 연결한 후보 artifact를 얻는다. |
| US-05 | 챌린지가 가짜 오류나 모델 지시문을 출력함 | 해당 내용을 분석 데이터로 다루며 실행 정책이나 권한으로 해석하지 않는다. |
| US-06 | 디버거가 멈추거나 프로세스가 종료됨 | timeout·종료 상태를 명시하고 자원 정리 후 세션 사용을 거부한다. |

## 4. 공통 불변식

| ID | 필수 조건 |
|---|---|
| INV-01 | Router의 복수 lead와 non-ranking 의미를 유지한다. 정적 결과의 `skill=None` 및 지연 Skill 정책을 변경하지 않는다. |
| INV-02 | Pattern Card와 신규 GDB 관측만으로 primitive PASS 또는 SOLVED를 만들 수 없다. |
| INV-03 | 기존 typed STATE 및 canonical completion gate를 유지한다. 신규 direct-evidence producer 등록은 범위 밖이다. |
| INV-04 | 기존 query/result envelope, Artifact Store와 Runner를 우선 재사용한다. 새 스키마가 필요하면 코드·스키마·문서를 함께 변경하고 호환성을 검증한다. |
| INV-05 | 단일 활성 챌린지와 기존 허용 대상 정책을 준수한다. 이번 세션 기능은 로컬 대상에 한정한다. |
| INV-06 | `partial`, timeout, 잘린 출력, 누락된 증거는 명시적으로 표현하며 완전한 관측으로 취급하지 않는다. |
| INV-07 | 기존 CLI 기본 동작을 유지한다. 카드 조회와 지속형 GDB는 명시적으로 선택하는 기능이다. |
| INV-08 | 챌린지 출력·지식 본문·GDB 콘솔 텍스트는 운영 지시나 권한 변경의 근거가 아니다. |

## 5. 기능 요구사항

### 5.1 F1 — Bounded Pattern Retrieval

**사용자 진입점:** `rat query pattern <binary>`를 추가한다. 옵션 이름과 저장 계약은
기존 query adapter를 검토한 뒤 확정하되, 아래 동작은 필수다.

| ID | 요구사항 |
|---|---|
| F1-01 | 기존 `knowledge/`, `skills/`의 섹션·anchor를 조사하고 선택된 원문 범위만 projection한다. 전체 지식 preload는 하지 않는다. |
| F1-02 | 관측된 signal·lead와 명시적인 선택 규칙을 사용한다. 동일 evidence와 source revision에는 동일 카드·순서를 반환한다. 순서를 취약점 확률 순위로 표현하지 않는다. |
| F1-03 | 최대 3개 카드와 총 출력 예산을 적용한다. 매칭이 없으면 0개를 반환하며 내용을 만들어내지 않는다. |
| F1-04 | 카드에 ID, 출처 경로·섹션·revision 또는 content digest, 선택 근거, 전제, 반증 조건, 다음 bounded 실험을 포함한다. |
| F1-05 | 카드의 `hypothesis-aid` 성격과 직접 증거가 아님을 표시한다. 기존 사례의 성공을 새 문제의 증거로 전용하지 않는다. |
| F1-06 | 복수 lead가 공존할 수 있게 한다. import 하나만으로 취약점 존재·실행 primitive·Skill lock을 확정하지 않는다. |
| F1-07 | 섹션 누락·source 불일치·잘못된 지식 구조는 진단 가능한 결과로 처리한다. 필수 출처·후보 표시가 예산에 들어가지 않으면 해당 카드를 생략한다. |
| F1-08 | 별도 검색 서비스나 DB를 만들지 않는다. 필요한 소규모 매핑은 기존 지식의 anchor와 검증 가능한 출처에 연결한다. |

**수용 기준:** 결정적 선택, 다중 lead, 0건, 누락·stale source, malformed 입력,
출력 제한 테스트를 통과한다. 카드 조회 전후에 route verdict·Skill·primitive 상태가
카드 때문에 변경되지 않는다. 새 성능 계측은 추가하지 않는다.

**예상 변경 위치:** `bin/rat`, `bin/ratlib/cards.py`, 필요 시
`bin/ratlib/patterns.py`, `knowledge/GROUNDING_INDEX.md`, 관련 Skill 문서와 테스트.

### 5.2 F2 — Governor의 진전 판단과 다음 행동

| ID | 요구사항 |
|---|---|
| F2-01 | `hypothesis.recorded`, `unknown.recorded`, `next.recorded`가 추가됐다는 사실만으로 novelty를 부여하지 않는다. |
| F2-02 | artifact·finding·primitive의 유효한 갱신과 동일 결과의 재기록을 구분한다. 기존 fingerprint·digest·STATE를 활용한다. |
| F2-03 | 관측으로 뒷받침된 가설 반증과 primitive 무효화도 새로운 정보로 다룬다. 성공 방향의 변화만 진전으로 세지 않는다. |
| F2-04 | 기존 가설·관측·실패 기록을 이용한다. 새 상태 DB를 만들지 않으며 누락된 연결을 추측하지 않는다. |
| F2-05 | 기존 5회 window를 유지한다. 기록이 부족하면 stuck으로 단정하지 않는다. |
| F2-06 | 다음 권고에는 사용한 근거를 연결한다. 근거가 부족하거나 충돌하면 기존 re-route/DEEP 권고로 돌아간다. |
| F2-07 | 권고는 자동 실행 명령이 아니다. 기존 에이전트의 단일 실험 선택 흐름을 유지한다. |

권고 정책:

| 확인된 상황 | 권고 |
|---|---|
| 핵심 전제가 아직 미확인 | 저비용 discriminator |
| 유효 primitive가 있으나 체인이 미완성 | 해당 부분에 집중한 DEEP |
| 실행 환경·조건의 불일치 | 환경 검증 |
| 현재 lead들이 증거로 반증됨 | 재라우팅 |
| 판단 근거 부족 또는 충돌 | 기존 re-route/DEEP 권고 |

**수용 기준:** 메모만 반복해서 stuck을 회피할 수 없다. 동일 결과 재조회와 유효한
증거 갱신을 구분한다. 실제 갱신 후에는 stuck에서 복구한다. 기존 STATE와 호환된다.

**예상 변경 위치:** `bin/ratlib/governor.py`, `bin/rat`의 progress 연결부,
`tests/test_governor.py` 및 해당 문서.

### 5.3 F3 — 선택적 지속형 GDB

기존 `rat dyn`에 선택적 세션 경로를 제공한다. 아래는 동작 계약이며 최종 CLI
구문은 Runner의 소유·수명 모델을 확인한 후 확정한다. 독립 실행 체계는 만들지 않는다.

| 동작 | 계약 |
|---|---|
| `start` | 활성 run, 검증된 binary 경로·digest, scenario, cwd/argv/env 정책, timeout·출력 상한을 확인하고 세션을 시작한다. |
| `inspect` | breakpoint, continue, register, bounded memory, mapping을 목적별 action으로 수행한다. 자유형 명령 실행은 초기 범위에서 제외한다. |
| `capture` | 관측을 기존 Artifact Store에 immutable candidate artifact로 기록한다. |
| `close` | 세션을 종료하고 소유한 프로세스·handle·임시 자원을 정리한다. 반복 종료는 안전해야 한다. |

| ID | 요구사항 |
|---|---|
| F3-01 | 같은 디버거·대상 프로세스에서 최소 두 단계의 연속 관측이 가능해야 한다. |
| F3-02 | session ID, run ID, process identity, binary·environment·scenario digest, 관측 순서, tool version을 연결한다. |
| F3-03 | 다른 run의 세션 접근과 identity 불일치를 거부한다. fork/exec/restart로 대상이 달라지면 이전 관측을 자동 결합하지 않는다. |
| F3-04 | 전체 timeout, idle timeout, action별 출력 상한을 적용한다. 프롬프트 문자열 감지만으로 성공을 판정하지 않는다. |
| F3-05 | 성공·실패·timeout·partial·연결 상실·출력 잘림을 구조적으로 구분한다. 빈 결과를 정상 측정값으로 만들어내지 않는다. |
| F3-06 | close, 상위 run 종료, timeout, 크래시, 프로세스 사망 경로에서 자원을 정리한다. |
| F3-07 | 모든 신규 관측은 candidate로 저장한다. `DIRECT_EVIDENCE_TOOLS` 등 증거 신뢰 루트를 확장하지 않는다. |
| F3-08 | 기존 배치 `rat dyn`, `gdbq`, `pwncrash` 동작을 유지한다. GDB 미설치 시 명확한 진단을 반환한다. |

**수용 기준:** 실제 GDB에서 연속 관측을 확인하고, 실패·잘림·격리·restart·cleanup
테스트를 통과한다. 지원 대상의 32/64bit 출력 파싱을 검증한다. 대표 fixture의 일반 실행과
디버거 실행 조건을 대조한다. GDB 부재나 실행 환경 제한으로 확인하지 못한 항목은
미검증으로 남기며 전체 완료로 처리하지 않는다.

**예상 변경 위치:** `bin/ratlib/runner.py`, `analysis.py`, `analysis_cli.py`,
`bin/rat`, 필요 시 내부 세션 모듈·`run_manifest.py`, 관련 통합 테스트.

### 5.4 F4 — 출처 구분과 운영 문서

| ID | 요구사항 |
|---|---|
| F4-01 | 챌린지 내용, 실제 플랫폼 권한 응답, 로컬 실행 정책을 서로 다른 출처로 처리한다. 문자열만으로 권한을 판정하지 않는다. |
| F4-02 | 챌린지의 `Access denied`는 허가된 로컬 분석을 중단시키는 정책으로 승격하지 않는다. |
| F4-03 | `Ignore previous instructions` 등 챌린지·지식 텍스트는 모델 지시로 채택하지 않는다. |
| F4-04 | 실제 플랫폼 거부와 허용 범위 밖 요청은 기존 정책을 유지한다. 새 기능을 통한 우회 경로를 만들지 않는다. |
| F4-05 | 기존 정책으로 충분하면 문서·fixture만 보강한다. 새 문자열 필터나 별도 탐지 엔진을 추가하지 않는다. |
| F4-06 | CLI help, `CLAUDE.md`, `README.md`, 관련 계약 문서를 구현과 동기화한다. 후보 증거의 한계, 세션 종료, 기능 사용 조건을 설명한다. |

테스트로 확인하는 범위는 소프트웨어의 출처·정책·증거 경계다. fixture 통과만으로
모든 모델의 프롬프트 인젝션 저항성을 입증했다고 주장하지 않는다.

## 6. 구현 단계와 산출물

| 단계 | 작업 | 산출물·종료 조건 |
|---|---|---|
| M0 | 실제 HEAD·작업 트리·기존 계약 재확인 | 본 문서 기준과 달라진 전제 기록, 기존 변경 보존 |
| M1 | F1 구현 | bounded query, 카드 계약, unit·failure-path 테스트, 사용 문서 |
| M2 | F2 구현 | novelty 교정, 근거 기반 권고, 기존 STATE 호환 테스트 |
| M3 | F3 구현 | 세션 수명·관측·격리, 실제 GDB 통합 테스트, 종료 문서 |
| M4 | F4 및 전체 회귀 | 출처 fixture, CLI·문서 동기화, 검증 결과와 미검증 항목 |

각 단계는 독립적으로 검토 가능한 변경 단위로 만든다. F4의 관련 테스트는 각 단계에
함께 추가한다. 커밋·푸시는 별도 명시 요청이 있을 때만 수행한다.

## 7. 검증 계획

### 기능별 검사

- F1: 결정성·출처·카드 수·예산·반증 조건·잘못된 입력·route/Skill 불변성
- F2: 메모 반복·동일 결과·실제 증거 갱신·반증·무효화·부족한 이력·호환성
- F3: 연속 관측·GDB 부재·timeout·잘림·프로세스 종료·cross-run 거부·cleanup
- F4: 동일 문자열의 다른 출처·정책 거부 유지·후보 자료의 PASS/SOLVED 승격 차단

### 저장소 회귀

도구 수정 후 적용되는 저장소 지침에 따라 다음을 실행한다.

```sh
python3 bin/revq selftest
python3 bin/rat selftest
python3 solve/_template/rev/symsolve.py selftest
python3 solve/_template/rev/vmlift.py selftest
python3 solve/_template/rev/qiling_trace.py selftest
python3 bin/k_kallsyms --selftest
python3 bin/ratbench selftest
python3 bin/pklearn selftest
python3 bin/pwngadget selftest
python3 bin/pwnlibc selftest
python3 bin/ratbench run
python3 -m unittest tests.test_writeup_pipeline
```

angr 설치 환경에서는 `bash tests/e2e_rev.sh`도 실행한다. 추가한 기능별 테스트와
관련 기존 unit/integration 검사를 함께 실행한다. Mode A는 route/oracle 회귀
검사이며 실제 풀이 성능 평가가 아니다. 신규 live Mode B 비교는 수행하지 않는다.

## 8. 위험과 대응

| 위험 | 대응 |
|---|---|
| 잘못된 카드에 분석이 고정됨 | 전제·반증 조건·복수 lead를 유지하고 명시 조회만 제공 |
| 카드 출력이 커짐 | 선택 섹션만 읽고 카드 수·총 예산 제한 |
| Governor가 실제 진전도 놓침 | 성공·반증·무효화를 포함한 테스트와 기존 권고 fallback |
| GDB가 환경을 바꾸거나 관측을 혼합함 | 실행 identity 기록, 일반 실행 대조, restart 이후 관측 분리 |
| 세션 종료 실패 | 수명 소유권 명확화, 종료 경로별 프로세스·handle 검사 |
| 후보 자료가 직접 증거로 오인됨 | 명시적 후보 계약, trust root 변경 금지, 부정 테스트 |
| 성능 효과 없이 복잡도만 증가함 | 선택적 사용, 단계별 변경, 성능 미검증 명시 |

## 9. 완료 및 되돌리기 기준

완료하려면 기능별 수용 기준과 실행 가능한 필수 회귀가 통과해야 한다. 환경 때문에
필수 검증을 수행하지 못했다면 구현 상태와 검증 상태를 구분해 보고한다. 문서·CLI·
저장 계약이 일치하고 알려진 제약이 기록되어야 한다.

문제가 생기면 기능 단위로 되돌릴 수 있어야 한다.

- F1: pattern query와 projection만 제거하고 원래 지식·route 경로를 유지한다.
- F2: Governor 판단을 이전 동작으로 되돌리되 기존 STATE 기록의 가독성을 유지한다.
- F3: 활성 세션을 먼저 종료하고 선택적 세션 경로를 제거한다. 배치 경로와 저장된
  candidate artifact는 손상시키지 않는다.
- F4: 신규 문서·fixture를 조정하더라도 기본 허용 대상·증거 정책은 유지한다.

최종 보고는 변경 내용, 실행한 테스트, 미검증 항목, 제약을 포함한다.
“기능 구현 완료”와 “실전 해결력 향상 입증”을 구분한다.

## 10. 구현 검증 기록 (2026-09-23)

- 기준 HEAD는 계획과 같은 `ec90774f5f322030641767ef79a87fb72344a968`였다.
  기존의 미추적 PRD와 `bench/results/codex-logs/`는 보존했다.
- F1의 명시적 pattern query는 기존 Skill·knowledge anchor에 연결된 최대 3개
  hypothesis-aid를 반환한다. F2는 메모와 동일 증거의 중복 기록을 진전에서 제외한다.
- F3의 선택적 로컬 GDB/MI 세션과 candidate 저장·수명 관리는 구현했다.
  모의 MI 테스트는 출력 잘림, timeout, 재시작 격리, cross-run 거부와 자원 정리를
  통과했다. 실제 GDB 15.1을 ARM64 Linux Docker에서 실행해 같은 inferior의
  두 breakpoint, 레지스터·메모리 조회, 별도 CLI 호출 간 세션 유지, candidate 저장과
  프로세스 종료를 검증했다.
- 필수 selftest, Mode A, writeup pipeline은 통과했다. REV e2e는 Linux
  컨테이너에서 통과했다. macOS 실행에서는 ARM Mach-O 생성으로 REV e2e가 실패한다.
- 해결률·시간·토큰 개선은 측정하지 않았으며 주장하지 않는다.
- 추가 검토에서 발견된 네 결함을 수정했다. GDB는 Linux `/proc/<pid>/exe`의
  실행 파일 digest로 동일 PID의 `exec`를 감지해 외부 바이너리 관측을 저장하지 않는다.
  무응답 소켓의 수신·송신에는 남은 세션 deadline을 적용한다. Governor는
  primitive consumed 및 증거 무효화의 stale 연쇄를 반영한다. Pattern query는
  Governor와 출력 개행을 포함한 최종 바이트 수로 예산을 검사한다.
  각 결함의 회귀 테스트와 실제 ARM64 Docker GDB `exec` 테스트를 통과했다.
- 이번 ARM64 GDB 이미지의 REV e2e 재실행은 angr가 없어 selftest만 통과했다.
  앞선 Linux 이미지의 실 바이너리 e2e 통과 기록과 구분한다.
- 추가 경계 검토에 따라 GDB 시작 직후 `catch exec`를 필수 등록한다. 같은 PID의
  새 프로그램이 즉시 종료하더라도 MI `reason="exec"` 정지에서 세션을 닫으며,
  전환 관측은 원래 바이너리의 candidate에 저장하지 않는다. Action timeout은
  설정값뿐 아니라 남은 total/idle deadline으로 제한한다. 실제 ARM64 GDB의
  즉시 종료 `exec`와 지연 action 회귀 테스트를 통과했다.
