# pwnable-note — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: note   **remote**: pwnable.kr:2222
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
============================================================
BIN   : ./note
FILE  : ./note: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, fo
PROT  : PIE=False Canary=False NX=True RELRO=Partial | stripped=False funcs=10
libc  : ./libc.so.6
SINK  : __isoc99_scanf, fgets, gets, read | fmt계열: printf
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
------------------------------------------------------------
TRIAGE: 🟡 STANDARD  | 확신도: 중간  → SOLVE (작업 필요)
  추정 기법: ROP (leak 필요)
  근거    : overflow, canary/libc 확인 필요
  다음    : decomp ./note <func> → vuln 확정 → state.md
============================================================
