# profile_migration — IN PROGRESS / STUCK ⏸

> 팀 공유용 handoff. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[✓ 됨]** guard active; local files extracted; chall stripped amd64 noPIE Full RELRO Canary NX; Docker ubuntu 26.04 xinetd port 31337
2. **[? 가설]** calibrate menu is a timing bit oracle over ctx mmap[record*0x200+offset], with libc FILE* pointers planted at offsets 0x290/0x6a0/0xab0; can leak stdout pointer bits for libc base
3. **[🧪 primitive]** `timing_libc_leak` = **PASS** — menu3 timing oracle over mmap table: record1+0x90 leaks stdout pointer bits; local measured stdout=0x7d36896045c0 on host libc, threshold ~0.185s; Docker libc 2.43 _IO_2_1_stdout_ offset=0x213580
4. **[🧪 primitive]** `slot7_tcache_uaf_write` = **BLOCKED** — edit empty slot7 length=0x88 alloc/free two 0x88 chunks then second edit writes to freed 0x90 tcache head; read_line writes len-1 bytes plus NUL, e.g. len=10 with 9-byte input returns index synchronized; needs heap chunk_addr for safe-link fd=target^(chunk>>12)
5. **[✗ 배제]** tcache poisoning to libc/stdout/stack — safe-linking glibc 2.43 requires heap chunk address or encoded fd leak; timing oracle leaks libc FILE pointers only
6. **[✗ 배제]** FSOP via stdout corruption — post-init output helper uses raw write, option5 calls _exit, no reachable stdio flush/call sink before arbitrary allocation/write
7. **[✗ 배제]** unsorted/largebin attack from invalid 0x500 import UAF — correction writes start at offsets selected from table (0x40/0x70/0xa0/0xd0 etc) with width<=0x30; cannot touch freed chunk fd/bk/fd_nextsize/bk_nextsize at user offsets 0x0..0x18
8. **[→ 다음]** Need missing bridge: heap leak/encoded tcache fd leak/write into first 0x20 bytes of freed 0x510 chunk/or post-corruption allocation path; otherwise blocked

## Gate Status
- Primitive: PASS
  - `timing_libc_leak`: menu3 timing oracle over mmap table: record1+0x90 leaks stdout pointer bits; local measured stdout=0x7d36896045c0 on host libc, threshold ~0.185s; Docker libc 2.43 _IO_2_1_stdout_ offset=0x213580
- Active hypotheses:
  - calibrate menu is a timing bit oracle over ctx mmap[record*0x200+offset], with libc FILE* pointers planted at offsets 0x290/0x6a0/0xab0; can leak stdout pointer bits for libc base

## 배제된 것 (재시도 금지)
- ❌ tcache poisoning to libc/stdout/stack — safe-linking glibc 2.43 requires heap chunk address or encoded fd leak; timing oracle leaks libc FILE pointers only
- ❌ FSOP via stdout corruption — post-init output helper uses raw write, option5 calls _exit, no reachable stdio flush/call sink before arbitrary allocation/write
- ❌ unsorted/largebin attack from invalid 0x500 import UAF — correction writes start at offsets selected from table (0x40/0x70/0xa0/0xd0 etc) with width<=0x30; cannot touch freed chunk fd/bk/fd_nextsize/bk_nextsize at user offsets 0x0..0x18

## 막힌 지점 / 다음 단계
- Need missing bridge: heap leak/encoded tcache fd leak/write into first 0x20 bytes of freed 0x510 chunk/or post-corruption allocation path; otherwise blocked

## 재현
- 스크립트: `exploit.py`
- 실행: `cd profile_migration && python3 exploit.py`
