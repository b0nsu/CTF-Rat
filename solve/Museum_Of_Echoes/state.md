# Museum_Of_Echoes — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: museum_of_echoes   **remote**: '-'
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
BIN   : ./museum_of_echoes
FILE  : ./museum_of_echoes: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-l
PROT  : PIE=True Canary=True NX=True RELRO=Full | stripped=False funcs=14
libc  : 미제공
SINK  : fgets, read | fmt계열: printf
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
HEAP  : free, malloc
FLAG  : flag 문자열/경로 감지
------------------------------------------------------------
TRIAGE: 🟠 HARD  | 확신도: 낮음  → 후순위 (확신 낮음)
  추정 기법: FSOP / House of *; tcache + safe-linking 우회
  근거    : heap + glibc 미상 (>=2.32: safe-linking; >=2.34: hooks 제거)
  다음    : decomp ./museum_of_echoes <func> → vuln 확정 → state.md
============================================================
