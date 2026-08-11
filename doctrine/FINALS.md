# 팀전 로컬 분석 운영 메모

> 이 문서는 자동 진입점이나 에이전트 작업 지시가 아니다. 기본 세션은 `CLAUDE.md`와 `doctrine/SOLVING.md`의 로컬 전용 규약만 따른다.

## 목적

여러 사람이 제공된 CTF artifact를 빠르게 분류하고, 로컬에서 재현 가능한 분석과 PoC를 공유한다. 외부 시스템 접속, 결과 획득, 제출은 이 문서의 범위 밖이다.

## 운영 루프

1. 제공된 바이너리·소스·libc·Docker를 문제별로 등록하고 `recon` 또는 `revq`로 우선순위를 정한다.
2. 한 문제에는 한 명의 주 담당자를 둔다. 필요한 경우에만 최대 3개의 로컬 분석 가설을 병렬 검토한다.
3. `state show` → decomp/도출 → primitive 로컬 실증 → `solve_local.py` 재현 → skeptic 반증 → `pkshare` 순서로 기록한다.
4. 기본 결과는 `HANDOFF.md`로 남기며, [WRITEUP_FORMAT.md](WRITEUP_FORMAT.md)의 상태·재현·증거·AI 사용 사실 기재 항목을 따른다. `PRIMITIVE_PASS`는 완료로 승격하지 않는다. 운영자가 후속 결과를 명시적으로 확인한 경우에만 `WRITEUP.md` 또는 `SUBMISSION.md`를 만든다.

## 완료 기준

- 독립된 로컬 환경에서 재현되는 분석 결론 또는 PoC가 있다.
- 입력·libc·loader·Docker·ASLR 등 재현 전제조건과 실패 조건을 기록했다.
- 외부 결과나 제출 상태를 완료 근거로 사용하지 않는다.

## 협업 규율

- `STATE.jsonl`을 단일 사실원으로 사용한다. 가설은 가설로, 실패는 `state no`로 즉시 기록한다.
- 자동 작업 인계나 외부 상호작용 위임은 하지 않는다. 막히면 공유물을 남기고 사람의 다음 지시를 기다린다.
