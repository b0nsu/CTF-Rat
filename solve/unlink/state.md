# unlink — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: unlink   **remote**: '-'
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
== libcgate: /home/ctfrat/CTF-Rat/solve/unlink ==
Dockerfile: none found
libc candidates:
  - none
loader candidates:
  - none
verdict:
  NOTE: No Dockerfile found: use supplied libc/ld when present; glibc-fetch is only a fallback.
  GATE: Before claiming remote libc mismatch, verify Docker-loopback behavior or leak/hash/build-id evidence.
  GATE: For heap/tcache failures, first prove tcache count/head/fd and safe-linking encoding on the exact malloc/free sequence.
============================================================
BIN   : ./unlink
FILE  : ./unlink: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, 
PROT  : PIE=False Canary=False NX=True RELRO=Partial | stripped=False funcs=6
libc  : 미제공
WIN?  : shell
SINK  : gets | fmt계열: printf
EXEC  : system=True execve=False syscall=False /bin/sh=True seccomp=False
HEAP  : malloc
------------------------------------------------------------
TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: FSOP / House of *; tcache + safe-linking 우회
  근거    : heap + glibc 미상 (>=2.32: safe-linking; >=2.34: hooks 제거)
  다음    : decomp ./unlink <func> → vuln 확정 → state.md
============================================================
