# dreamhack_1286 — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: prob   **remote**: '-'
- **arch/prot**: (recon 결과 붙여넣기)
- **libc**: (버전 / 경로)
- **vuln class**: (stack overflow / fmt / heap-UAF / …)
- **stage**: recon

## offsets
| 이름 | 값 | 확인방법 |
|---|---|---|
| buf→ret | ? | cyclic |

## leaks / gadgets
- libc base: ?
- pop rdi: ?   ret: ?   one_gadget: ?

## plan (체크리스트)
- [ ] recon + triage
- [ ] vuln 함수 확정 (decomp)
- [ ] primitive 확보
- [ ] leak
- [ ] 최종 exploit → flag

## notes
(막힌 지점 / 시도한 것 / 다음 아이디어)

---
### recon
== libcgate: /home/ctfrat/CTF-Rat/solve/dreamhack_1286 ==
Dockerfile:
  - Dockerfile  [FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac]
libc candidates:
  - none
loader candidates:
  - none
verdict:
  WARN: Dockerfile exists but no extracted libc candidate was found in this directory.
  WARN: Dockerfile exists but no extracted ld-linux candidate was found in this directory.
  NOTE: Dockerfile present: built image is authoritative for libc, loader, env, cwd, user, and wrapper.
  GATE: Before claiming remote libc mismatch, verify Docker-loopback behavior or leak/hash/build-id evidence.
  GATE: For heap/tcache failures, first prove tcache count/head/fd and safe-linking encoding on the exact malloc/free sequence.
============================================================
BIN   : ./prob
FILE  : ./prob: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.
PROT  : PIE=True Canary=False NX=True RELRO=Full | stripped=False funcs=4
libc  : 미제공
SINK  : __isoc99_scanf, read | fmt계열: printf
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
HEAP  : free, malloc
------------------------------------------------------------
TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: FSOP / House of *; tcache + safe-linking 우회
  근거    : heap + glibc 미상 (>=2.32: safe-linking; >=2.34: hooks 제거)
  다음    : decomp ./prob <func> → vuln 확정 → state.md
============================================================
