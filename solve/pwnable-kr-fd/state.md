# pwnable-kr-fd — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: pwnable-kr-fd   **remote**: fd@pwnable.kr:2222
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
== libcgate: /home/ctfrat/CTF-Rat/solve/pwnable-kr-fd ==
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
[FACT] 직접 ELF/문자열 파싱 관측 (취약점 확정 아님)
BIN   : ./pwnable-kr-fd
FILE  : ./pwnable-kr-fd: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-l
PROT  : PIE=True Canary=False NX=True RELRO=Full | stripped=False funcs=3
libc  : 미제공
SIGNAL sink : read | fmt계열: -
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
------------------------------------------------------------
[ROUTE] TRIAGE: 🟡 STANDARD  | 확신도: 중간  → SOLVE (작업 필요)
  추정 기법: ROP (leak 필요)
  근거    : overflow, canary/libc 확인 필요
  다음    : decomp ./pwnable-kr-fd <func> → vuln 확정 → state.md
============================================================
