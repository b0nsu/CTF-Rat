# damnida — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: damnida   **remote**: '-'
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
== libcgate: /home/ctfrat/CTF-Rat/solve/damnida ==
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
BIN   : ./damnida
FILE  : ./damnida: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-
PROT  : PIE=True Canary=True NX=True RELRO=Full | stripped=False funcs=7
libc  : 미제공
SINK  : read | fmt계열: printf
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
------------------------------------------------------------
TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: 미상 — decomp 로 vuln 확인
  근거    : 정적 신호 부족
  다음    : decomp ./damnida <func> → vuln 확정 → state.md
============================================================
