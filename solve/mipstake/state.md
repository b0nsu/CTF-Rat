# mipstake — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: mipstake   **remote**: pwnable.kr:10047
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
== libcgate: /home/ctfrat/CTF-Rat/solve/mipstake ==
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
BIN   : ./mipstake
FILE  : ./mipstake: ELF 32-bit MSB executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for 
PROT  : PIE=False Canary=False NX=False RELRO=None | stripped=True funcs=3
libc  : 미제공
SIGNAL sink : - | fmt계열: printf
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
[!] stripped — 심볼기반 신호(win/함수명) 신뢰 불가, triage 확신도 하향
------------------------------------------------------------
[ROUTE] TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: format-string 후보 (decomp로 printf(user) 확인 — 정적 확신 불가)
  근거    : printf 계열 존재
  다음    : decomp ./mipstake <func> → vuln 확정 → state.md
============================================================
