# Calibration log — 기준(SOLVABILITY) 정밀도 실증 (정직 모드: 답/writeup 미참조)

> **로컬 전용 누적 로그.** 각자 자신의 정직 모드 도출 결과만 여기에 쌓는다.
> 실제 flag·remote·오프셋 상수를 담으므로 doctrine 경로 밖 `docs/`에 둔다
> (오염 금지 하드룰 상 doctrine에 상주 금지). 릴리스 시 이 파일은 빈 템플릿이며,
> recall로 채우지 않는다 — recall 기반 "확신"은 calibration을 무효화한다
> ([doctrine/SOLVABILITY.md](../doctrine/SOLVABILITY.md) 참조).

## 기록 형식

라벨 코퍼스(예: NYU pwn `initial` 점수 · pwnable.kr 점수)에서 **정직 모드**(답 미참조)로
도출·실증하며 아래 표에 누적한다. SOLVE 판정의 **정밀도**(확신인데 실패=false positive)를
측정해 게이트 조정에 쓴다.

| 챌린지 | prior tier | 도출 방식 | 결과 | FP/FN · 비고 |
|---|---|---|---|---|
| _(여기에 자신의 정직 도출 결과를 누적)_ | | | | |

## 관찰 (기준에 반영)

_(도출 과정에서 얻은, SOLVABILITY 게이트에 반영할 일반화된 관찰만 기록. 특정 flag·주소는 위 표에.)_
