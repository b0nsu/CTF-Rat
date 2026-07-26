# do_wargame_zip — IN PROGRESS / STUCK ⏸

> 팀 공유용 handoff. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[? 가설]** main uses scanf("%s") into 0x100-byte stack buffer; saved RIP offset expected 0x108, needs SELF primitive check
2. **[🧪 primitive]** `rip_control` = **PASS** — local core: offset=0x108 overwrites saved RIP with marker; scanf %s terminates on newline and appends NUL
3. **[🧪 primitive]** `rip_control` = **PASS** — verified local core: offset=0x108, fault_addr=0x4948474645444342 (BCDEFGHI little-endian), scanf %s newline terminates and NUL follows payload
4. **[📏 측정]** `rip_offset = 0x108`  (core fault_addr marker)
5. **[📏 측정]** `bss_rbp = 0x404800`  (writable .bss for one_gadget rbp constraints)
6. **[🧪 primitive]** `local_shell` = **PASS** — Ubuntu 22.04 libc 2.35 via prob_235: one_gadget 0xebdaf with rbp=0x404800 produced shell and id output
7. **[🧪 primitive]** `remote_partial` = **FAIL** — 800+ remote attempts with 3-byte partial overwrite produced no shell; scanf NUL terminator corrupts high address byte, route invalid without preserving upper bytes
8. **[✗ 배제]** remote 3-byte partial one_gadget brute — real Docker libc base is page-aligned with broad ASLR, not 0x100000-aligned; scanf appends NUL so partial overwrite corrupts next address byte; 800+ attempts no hit
9. **[✗ 배제]** automatic ret2dlresolve via pwntools — binary has no pop rdi/csu gadget; pwntools cannot satisfy rdi for system("/bin/sh")
10. **[? 가설]** possible remaining route: manual ret2dlresolve if rdi can be made to point to /bin/sh, or stack-reentry trick using existing libc pointers without knowing ASLR
11. **[✗ 배제]** remote ASLR/partial-overwrite brute — probabilistic remote brute, unintended; violates common anti-bruteforce rule without remote-equivalent leak/control primitive
12. **[🧪 primitive]** `bss_write` = **PASS** — local: saved rbp=0x404900 + ret main+0x8 causes second scanf to write attacker bytes at 0x404800; after scanf rbp=0x404900 and bss marker verified
13. **[✗ 배제]** fixed-address ret2dlresolve from bss pivot — Full RELRO/BIND_NOW leaves GOT[2] lazy resolver slot zero; plt0/0x40103a crashes at RIP=0 before _dl_runtime_resolve
14. **[✗ 배제]** libc partial overwrite pop-rdi route — scanf %s appends NUL after payload; preserving ASLR byte3 for libc target requires unknown byte, so remote path becomes ASLR brute-force
15. **[→ 다음]** Only remaining apparent path is probabilistic remote ASLR brute, which is prohibited by CTF-Rat ROE; need an additional deterministic leak/control primitive or challenge-side ASLR-off evidence

## Gate Status
- Primitive: PASS
  - `rip_control`: local core: offset=0x108 overwrites saved RIP with marker; scanf %s terminates on newline and appends NUL
  - `rip_control`: verified local core: offset=0x108, fault_addr=0x4948474645444342 (BCDEFGHI little-endian), scanf %s newline terminates and NUL follows payload
  - `local_shell`: Ubuntu 22.04 libc 2.35 via prob_235: one_gadget 0xebdaf with rbp=0x404800 produced shell and id output
  - `bss_write`: local: saved rbp=0x404900 + ret main+0x8 causes second scanf to write attacker bytes at 0x404800; after scanf rbp=0x404900 and bss marker verified
- Active hypotheses:
  - main uses scanf("%s") into 0x100-byte stack buffer; saved RIP offset expected 0x108, needs SELF primitive check
  - possible remaining route: manual ret2dlresolve if rdi can be made to point to /bin/sh, or stack-reentry trick using existing libc pointers without knowing ASLR

## 검증된 오프셋/상수 (live 측정)
| key | value | src |
|---|---|---|
| `rip_offset` | `0x108` | core fault_addr marker |
| `bss_rbp` | `0x404800` | writable .bss for one_gadget rbp constraints |

## 배제된 것 (재시도 금지)
- ❌ remote 3-byte partial one_gadget brute — real Docker libc base is page-aligned with broad ASLR, not 0x100000-aligned; scanf appends NUL so partial overwrite corrupts next address byte; 800+ attempts no hit
- ❌ automatic ret2dlresolve via pwntools — binary has no pop rdi/csu gadget; pwntools cannot satisfy rdi for system("/bin/sh")
- ❌ remote ASLR/partial-overwrite brute — probabilistic remote brute, unintended; violates common anti-bruteforce rule without remote-equivalent leak/control primitive
- ❌ fixed-address ret2dlresolve from bss pivot — Full RELRO/BIND_NOW leaves GOT[2] lazy resolver slot zero; plt0/0x40103a crashes at RIP=0 before _dl_runtime_resolve
- ❌ libc partial overwrite pop-rdi route — scanf %s appends NUL after payload; preserving ASLR byte3 for libc target requires unknown byte, so remote path becomes ASLR brute-force

## 막힌 지점 / 다음 단계
- Only remaining apparent path is probabilistic remote ASLR brute, which is prohibited by CTF-Rat ROE; need an additional deterministic leak/control primitive or challenge-side ASLR-off evidence

## 재현
- 스크립트: `exploit.py`
- 실행: `cd do_wargame_zip && python3 exploit.py`
