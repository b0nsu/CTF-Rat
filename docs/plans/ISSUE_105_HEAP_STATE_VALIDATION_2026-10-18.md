# #105 heap-state 관측 헬퍼 — 실환경 검증 기록

작성일: 2026-10-18 (KST). 브랜치 `fix/issue105-heap-state-20261018` (base dev `08c5c92`).

## 결론

**#105의 기능 본체는 PR #111로 이미 `dev`에 구현돼 있다**(`rat dyn session heap`,
`bin/ratlib/gdb_session.py:_heap_snapshot`). 남아 있던 종결 조건 —
"실제 로컬 glibc-2.35 대상에서 tcache/top/last_remainder/unsorted/decoded fd를
GDB 원값과 대조" — 을 이번에 수행했고 **PASS**. 독립 GDB가 읽은 원값과 세션
스냅샷이 **완전히 일치**한다. 이를 재현 가능한 regression 테스트로 승격했다.

이슈 본문이 제안한 UI(`rat query pwn <bin> --heap-state <pid>` / 임의 PID attach)는
의도적으로 채택하지 않았다: 정적 capability card 경로(`cmd_query_pwn`)에 live 관측을
끼우는 것은 의미론적으로 어긋나고, 임의 PID attach는 kit의 ROE(로컬 owned-run만,
ctfguard ACTIVE.json 매치)를 훼손한다. 등가 기능은 `rat dyn session heap`로 제공된다.

## 검증 방법 (MEASURED)

환경: Docker `ubuntu:22.04` = **glibc 2.35-0ubuntu3.15** (= `HEAP_LAYOUT`과 일치),
gdb 12.1, gcc 11.4, libc6-dbg. `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`.
(동일 테스트가 호스트 glibc 2.39에서도 PASS — version-agnostic.)

1. tcache를 결정론적으로 채우는 바이너리(`-no-pie`, ASLR off): `malloc/free` 5×0x18,
   2×0x38 → tcache bin idx0 count=5, idx2 count=2. `breakpoint_here()`에서 정지.
2. **Ground truth**: 독립 GDB가 `tcache`/`&main_arena`를 resolve하고,
   세션이 읽는 것과 **동일한 바이트 범위**(tcache base..+640, arena+0x60..+32)를
   `dump binary memory`로 떠서 `_heap_snapshot`과 **동일한 산술**로 디코드.
3. **세션**: `rat dyn session start → break breakpoint_here → continue → heap
   --layout glibc-2.35-x86_64 --tcache <addr> --arena <addr>`.
4. 두 결과를 대조.

## 결과 (PASS)

| 항목 | Ground truth (독립 GDB) | 세션 `rat dyn session heap` | 일치 |
|---|---|---|---|
| tcache bins | idx0 count=5 head=0x405320, idx2 count=2 head=0x405380 | 동일 | ✅ |
| arena.top | 0x4053b0 | 0x4053b0 | ✅ |
| last_remainder | 0x0 | 0x0 | ✅ |
| unsorted fd/bk | 0x7ffff7fa7ce0 | 0x7ffff7fa7ce0 | ✅ |
| 등급 | — | `direct_evidence=false` (candidate) | ✅ |

ROE 준수: ctfguard lock + active run + **owned inferior 전용**(임의 PID attach 없음),
bounded read(256B/req, 1024B cap), candidate artifact(`rat.gdb-session-candidate/v1`).

## 재현

`tests/test_gdb_session_v21.py::RealGdbSession::test_heap_snapshot_matches_independent_gdb_ground_truth`
— gcc/gdb 가드. 세션 스냅샷을 독립 GDB가 읽은 **동일 raw 바이트**의 디코드와 대조하므로
glibc 버전·절대주소에 의존하지 않는다("세션이 올바로 읽고 디코드하는가"를 검증).

```sh
python3 -m unittest tests.test_gdb_session_v21.RealGdbSession.test_heap_snapshot_matches_independent_gdb_ground_truth
```

## 남는 후속(별도 이슈 권고)

- interactive stdin (allocator 조작 사이 입력 주입)은 현 세션이 미지원
  (`docs/GDB_SESSION.md` 명시). #105 범위가 아니라 별도 이슈로 분리.
