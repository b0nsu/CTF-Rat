# QuarantineJournal — exploit working memory
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
== libcgate: /home/ctfrat/CTF-Rat/solve/QuarantineJournal ==
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
BIN   : ./prob
FILE  : ./prob: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=5e61c6f372c46d8f438d2
PROT  : PIE=False Canary=False NX=True RELRO=Partial | stripped=True funcs=0
libc  : 미제공
SINK  : - | fmt계열: -
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
[!] stripped — 심볼기반 신호(win/함수명) 신뢰 불가, triage 확신도 하향
------------------------------------------------------------
TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: 미상 — decomp 로 vuln 확인
  근거    : 정적 신호 부족
  다음    : decomp ./prob <func> → vuln 확정 → state.md
============================================================
