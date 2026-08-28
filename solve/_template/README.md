# solve/_template — 챌린지 스캐폴드 원본

`newchal <name> <bin> [libc]`가 이 디렉터리를 소스로 새 `solve/<name>/` 작업 공간을 만든다.
직접 편집하는 건 **템플릿 자체를 고칠 때뿐**이다. 실제 풀이는 항상 `solve/<name>/`에서 한다.

## 구성

| 파일 | 역할 | 사용 방식 |
|---|---|---|
| `state.md` | 챌린지별 working-memory 템플릿 (`{{NAME}}`/`{{BIN}}`/`{{REMOTE}}` 치환자 포함) | `newchal`이 치환자를 채워 `solve/<name>/state.md`로 **인스턴스화**한다. 원본은 실행하지 않는다. |
| `rev/symsolve.py` | angr symbolic 하니스 (+concrete-verify) | rev 스크립트는 인스턴스화하지 않고 **in-place로 실행**한다: `python3 solve/_template/rev/symsolve.py <bin> --find-str ...` (또는 PATH shim `symsolve`). |
| `rev/vmlift.py` | custom-VM 리프터 스캐폴드 | 동일하게 in-place 실행: `python3 solve/_template/rev/vmlift.py --disasm ...` (shim `vmlift`). |
| `rev/qiling_trace.py` | PE 동적 에뮬(Qiling, rootfs 필요 — SETUP §8) | in-place 실행. |

## 두 가지 패턴 요약

- **state.md = 인스턴스화**: `newchal`이 복사·치환해 문제 디렉터리에 놓는다. 템플릿은 "틀"이다.
- **rev/*.py = in-place 실행**: 복사하지 않고 이 경로(또는 PATH shim)에서 바로 돌린다. 챌린지 바이너리를 인자로 넘긴다.

> STATE는 `state` 버스(typed v2)에 기록한다. offset/primitive는 재도출하지 말고 evidence-backed observation으로 남긴다 — `doctrine/PRIMITIVE_GATE.md`.
