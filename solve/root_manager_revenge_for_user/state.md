# root_manager_revenge_for_user — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: root_manager_revenge   **remote**: '-'
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
== libcgate: /home/ctfrat/CTF-Rat/solve/root_manager_revenge_for_user ==
Dockerfile:
  - Dockerfile  [FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782 AS dependency-build]
  - public/Dockerfile  [FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782 AS dependency-build]
libc candidates:
  - libc.so.6 sha256=d8db8739a1633c97 glibc=2.39
  - public/libc.so.6 sha256=d8db8739a1633c97 glibc=2.39
loader candidates:
  - public/ld-linux-x86-64.so.2 sha256=1cd555ac46b7887e glibc=2.39
verdict:
  NOTE: Dockerfile present: built image is authoritative for libc, loader, env, cwd, user, and wrapper.
  GATE: Before claiming remote libc mismatch, verify Docker-loopback behavior or leak/hash/build-id evidence.
  GATE: For heap/tcache failures, first prove tcache count/head/fd and safe-linking encoding on the exact malloc/free sequence.
============================================================
BIN   : ./root_manager_revenge
FILE  : ./root_manager_revenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/
PROT  : PIE=True Canary=True NX=True RELRO=Full | stripped=True funcs=0
libc  : 2.39
SINK  : read | fmt계열: -
EXEC  : system=False execve=False syscall=True /bin/sh=False seccomp=False
HEAP  : free, malloc
[!] stripped — 심볼기반 신호(win/함수명) 신뢰 불가, triage 확신도 하향
------------------------------------------------------------
TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: FSOP / House of *; tcache + safe-linking 우회
  근거    : heap + glibc 2.39 (>=2.32: safe-linking; >=2.34: hooks 제거)
  다음    : decomp ./root_manager_revenge <func> → vuln 확정 → state.md
============================================================
