# do_wargame_zip — exploit working memory
> context 압축돼도 여기서 재-orient. 주소/offset은 반드시 확인 후 기록.

- **binary**: prob   **remote**: '-'
- **arch/prot**: amd64, no PIE, no canary, NX, Full RELRO, SHSTK/IBT notes present
- **libc**: Docker Ubuntu 22.04 glibc 2.35, copied to `./libc.so.6`
- **vuln class**: stack overflow via `scanf("%s")` into 0x100-byte stack buffer
- **stage**: local shell verified; waiting for remote target

## offsets
| 이름 | 값 | 확인방법 |
|---|---|---|
| buf→ret | 0x108 | local core fault marker `BCDEFGHI` |
| controlled rbp | 0x404800 | writable `.bss`, satisfies one_gadget rbp writable constraints |

## leaks / gadgets
- libc base: no program leak; local verification uses `/proc/<pid>/maps`, remote path brute-forces partial overwrite
- pop rdi/pop rsi/syscall: none
- tiny gadgets: `ret=0x40101a`, `pop rbp; ret=0x40111d`, `leave; ret=0x401168`
- one_gadget: glibc 2.35 `0xebdaf` and `0xebdb3` verified locally with `rbp=0x404800`

## plan (체크리스트)
- [x] recon + triage
- [x] vuln 함수 확정 (decomp)
- [x] primitive 확보
- [x] local one_gadget shell
- [ ] remote brute → flag once target is provided

## notes
- `main`: `scanf("%s", rbp-0x100); return 0;`
- Normal leak is unavailable: only imported function is `__isoc99_scanf`, Full RELRO, no useful CSU/pop-rdi.
- `scanf("%s")` appends a trailing NUL, so the remote exploit uses 3-byte saved-RIP partial overwrite and loops over 16 low-24 libc alignment candidates; success also depends on the ASLR byte overwritten by scanf's NUL being zero.
- Local challenge-libc shell proof: `prob_235` patched with Docker glibc 2.35 loader, payload `A*0x100 + p64(0x404800) + p64(libc_base+0xebdaf)` produced `PWNED` and `id`.

---
### recon
============================================================
BIN   : ./prob
FILE  : ./prob: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2
PROT  : PIE=False Canary=False NX=True RELRO=Full | stripped=False funcs=3
libc  : 미제공
SINK  : __isoc99_scanf | fmt계열: -
EXEC  : system=False execve=False syscall=False /bin/sh=False seccomp=False
------------------------------------------------------------
TRIAGE: 🟡 STANDARD  | 확신도: 중간  → SOLVE (작업 필요)
  추정 기법: ROP (leak 필요)
  근거    : overflow, canary/libc 확인 필요
  다음    : decomp ./prob <func> → vuln 확정 → state.md
============================================================
