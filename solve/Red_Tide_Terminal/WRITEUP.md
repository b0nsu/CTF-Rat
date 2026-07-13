# Red_Tide_Terminal — SOLVED ✅

> 팀 공유용 writeup. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[⚠ 전환점]** Remote binary differs from downloadable PIE+canary build: remote is non-PIE and exploitable frame behaves no-canary; local exploit offsets are not valid for remote.
2. **[📏 측정]** `rip_offset = 104`  (remote full-read overflow oracle + write(1,banner) ROP verify)
3. **[📏 측정]** `saved_rbp_offset = 96`  (remote route_packet frame)
4. **[📏 측정]** `pop_rdi = 0x4013ec`  (remote arbitrary-read gadget farm)
5. **[📏 측정]** `pop_rsi = 0x4013f5`  (remote arbitrary-read gadget farm)
6. **[📏 측정]** `pop_rdx = 0x4013fe`  (remote arbitrary-read gadget farm)
7. **[📏 측정]** `pop_rax = 0x401407`  (remote arbitrary-read gadget farm)
8. **[📏 측정]** `syscall_ret = 0x401410`  (remote arbitrary-read gadget farm)
9. **[📏 측정]** `leave_ret = 0x4013e6`  (remote arbitrary-read gadget farm)
10. **[✓ 됨]** Remote control-flow verified with write(1, 0x40205c, 0x28), printing the Red Tide banner.
11. **[✓ 됨]** Remote exploit verified: stage1 reads ORW chain into .bss and pivots with leave_ret; stage2 openat/read/write reads flag.txt.
12. **[✗ 배제]** Downloaded PIE+canary exploit.py path for remote — remote challenge service runs a different non-PIE/CET-shifted build; use exploit_remote.py offsets instead.
13. **[🔎 정찰/맥락]** Flag recovered, not auto-submitted: grodno{324d2c61-ea1c-40db-bf53-f361c5e3ad21}
14. **[🔎 정찰/맥락]** Reproducer: exploit_remote.py; remote entry used during solve: 10.112.0.12:47209.

## 검증된 오프셋/상수 (live 측정)
| key | value | src |
|---|---|---|
| `rip_offset` | `104` | remote full-read overflow oracle + write(1,banner) ROP verify |
| `saved_rbp_offset` | `96` | remote route_packet frame |
| `pop_rdi` | `0x4013ec` | remote arbitrary-read gadget farm |
| `pop_rsi` | `0x4013f5` | remote arbitrary-read gadget farm |
| `pop_rdx` | `0x4013fe` | remote arbitrary-read gadget farm |
| `pop_rax` | `0x401407` | remote arbitrary-read gadget farm |
| `syscall_ret` | `0x401410` | remote arbitrary-read gadget farm |
| `leave_ret` | `0x4013e6` | remote arbitrary-read gadget farm |

## 배제된 것 (재시도 금지)
- ❌ Downloaded PIE+canary exploit.py path for remote — remote challenge service runs a different non-PIE/CET-shifted build; use exploit_remote.py offsets instead.

## 재현
- 스크립트: `exploit.py`, `exploit_remote.py`
- 실행: `cd 66_Red_Tide_Terminal && python3 exploit_remote.py`
