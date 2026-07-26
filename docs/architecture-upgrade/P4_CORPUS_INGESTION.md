# P4 실제 corpus ingestion 계획

## 판정

`benchmarks/corpus/v1`은 P4 release corpus가 아니다. 2026-07-22 감사 시 manifest 40개 모두가
`CC0-1.0 synthetic fixture`를 선언하고 `src/fixture.py`를 실행한다. 40개 fixture의 파일 내용은 모두 동일하며,
40개 checker도 모두 동일하다. manifest의 source/binary/container digest는 `000…`, `111…`, `222…` placeholder다.
또한 corpus 아래에 Python/YAML 이외의 compiled executable artifact가 없다.

fixture는 정확히 `solve:<challenge-id>` 입력을 받으면 `verified:<challenge-id>`를 출력하고, checker는 그 문자열만
승인한다. 따라서 pwn 취약점, rev validation path, libc/rootfs, VM/obfuscation, intermediate observation을 검증하지
않는다. 이는 runner/collector smoke test에는 유효하지만 B027, PDF 17.1의 “Docker 또는 고정 VM으로 재현 가능한
challenge + intermediate ground truth” 완료 증거가 될 수 없다.

## 분리 원칙

- 현 `benchmarks/corpus/v1`은 `fixture-smoke` 전용으로 유지한다. release/nightly 분모와 baseline lock에는 넣지 않는다.
- 실제 자산은 `benchmarks/corpus/real-v1/<id>/`에 별도 ingest한다. 실제 40개가 준비될 때까지 P4 상태는 incomplete다.
- remote CTF 서버, 계정, 제출 endpoint는 corpus에 넣지 않는다. 모든 oracle은 local/container/고정 VM에서 실행한다.
- expected flag, 정답 입력, full ground truth는 solver workspace에 복사하지 않는다. evaluator 전용으로 capability를
  분리하고, solver에는 성공/실패와 허용된 observation validator 결과만 돌려준다.

## Pilot inventory (2026-07-26)

`benchmarks/corpus/real-v1/`에는 release-eligible 14개 pilot이 있다.
모두 local x86_64 build, source/binary SHA-256, evaluator-only executable oracle,
positive/negative control 및 3회 반복 실행을 가진다. 현재 분포는
stack-format 7, native rev 4, VM/obfuscation 3이며 모두 `calibration` split이다.
두 JerseyCTF-derived 항목은 MIT provenance를, 나머지 12개는 CC0 self-authored
flag-free adaptation provenance를 가진다. `validate_corpus(..., strict=False)`와
`production_readiness` API가 이 pilot의 release eligibility를 검사한다. CLI
`rat-bench validate-corpus`는 의도적으로 동결된 40개 분포만 승인한다.

이 pilot은 40개 production corpus나 PDF 목표 분포의 완료 선언이 아니다. 특히
heap, advanced, platform, regression과 holdout split이 아직 비어 있으므로 A0~A5
release matrix의 분모로 사용하지 않는다.

`benchmarks/corpus/pwnable-local-pilot/pwnable-kr-fd`는 pwnable.kr 공개
`fd` source로부터 만든 local build/oracle ingestion pilot이다. positive와
negative oracle은 통과했지만 upstream redistribution license가 명시되지
않았으므로 `redistributable: false`이며 `real-v1` 또는 release denominator에
넣지 않는다. 권리 확인 후에만 digest를 유지한 채 release candidate로
승격할 수 있다.

## 한 challenge의 ingestion gate

아래 항목이 모두 갖춰진 challenge만 `real-v1`에 추가한다.

1. **권리와 출처** — upstream URL/revision, license, redistribution 상태, maintainer attribution을 manifest에 기록한다.
   재배포 불가이면 immutable fetch recipe와 upstream SHA-256을 기록하되, CI가 credential/network에 의존하면 안 된다.
2. **재현 build** — source 또는 허가된 binary, Dockerfile/고정 VM recipe, compiler/toolchain/rootfs/libc/loader digest,
   deterministic seed와 architecture를 넣는다. clean container에서 build 후 binary digest가 manifest와 일치해야 한다.
3. **실행 scenario** — stdin/file/argv/socket harness와 resource limit을 제공한다. pwn은 local container target만,
   rev는 입력 검증 binary를 실제로 재실행한다. challenge source를 agent prompt에 주는 것은 별도 source-available track으로
   표시한다.
4. **독립 oracle** — solver output을 challenge 또는 evaluator가 실행해 success effect를 확인한다. oracle은 challenge-id
   문자열 비교가 아니라 실제 flag/token validation, protected branch, exploit side-effect, 또는 expected exit/output effect를
   검사한다. oracle source/mount는 runner와 분리한다.
5. **중간 truth** — primary category/location, required fact, finding, primitive-or-solution, observation locator와 tolerance를
   evaluator truth에 저장한다. pwn에는 control/leak/allocation/mitigation 증거, rev에는 validation path/semantic/input
   evidence가 최소 하나씩 있어야 한다.
6. **검증** — clean build, negative input, positive reference solve, oracle isolation, 3회 deterministic repeat를 통과한다.
   flaky/timeout은 quarantine하며 조용히 분모에서 제외하지 않는다.

## 40개로 가는 순서

1. 사용자가 제공하거나 재배포가 명확한 공개 challenge bundle을 후보 inventory에 등록한다. 현재 저장소의 `solve/` 파일은
   provenance/권리/reproducible oracle을 다시 확인하기 전에는 후보일 뿐 corpus가 아니다.
2. 각 영역에서 2개씩(총 14개) ingestion gate를 끝내 pilot으로 삼고 A0/A3 dry run을 한다. 여기서 manifest/schema와
   oracle isolation 문제를 고친다.
3. PDF 분포(7 stack-format, 6 heap, 5 advanced, 6 native, 6 VM/obfuscation, 5 platform, 5 regression)와
   난이도(14/16/10)를 채운다. calibration 24/holdout 16 split은 **truth를 보기 전에** manifest에 동결한다.
4. independent reviewer 두 명이 자산 provenance, build digest, oracle isolation, truth locator를 검사한다.
   review 기록과 corpus digest를 baseline lock에 넣는다.
5. 그 뒤에만 23-run release matrix(A0~A5 cold 3회, A1~A5 warm 1회)를 실제 40개에 실행하고 PDF/paired gate를 판정한다.

## 사용자에게 필요한 입력

실제 P4를 진행하려면 최소한 다음 중 하나가 필요하다.

- 재배포 가능한 CTF pwn/rev challenge bundle 40개(또는 우선 pilot 14개)의 로컬 경로와 license/source 정보
- 허가된 upstream archive/commit 목록 및 offline fetch 가능한 artifact digest
- 자체 제작 challenge라면 source, build recipe, intended solve/reference validator와 redistribution 허가

remote host:port나 live competition credential만 있는 문제는 받지 않는다. 해당 자산은 local/containerized benchmark로
변환할 수 있을 때만 scope에 넣는다.
