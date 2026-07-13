# Red_Tide_Terminal_Revenge — SOLVED ✅

> 팀 공유용 writeup. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[⚠ 전환점]** Remote binary differs from downloadable PIE+canary build: remote is non-PIE/no-canary for exploitable frame; local PIE/canary chain is not valid remotely.
2. **[📏 측정]** `rip_offset = 88`  (remote write(1,banner) ROP verify)
3. **[📏 측정]** `stack_leak_fmt = %7$p`  (remote audit-note format string)
4. **[📏 측정]** `stack_stage_delta = 0xa0`  (remote raw-syscall second read verified)
5. **[📏 측정]** `io_buf = 0x4040a0`  (remote writable buffer for ORW output)
6. **[📏 측정]** `pop_rdi = 0x4013ec`  (remote arbitrary-read gadget farm)
7. **[📏 측정]** `pop_rsi = 0x4013f5`  (remote arbitrary-read gadget farm)
8. **[📏 측정]** `pop_rdx = 0x4013fe`  (remote arbitrary-read gadget farm)
9. **[📏 측정]** `pop_rax = 0x401407`  (remote arbitrary-read gadget farm)
10. **[📏 측정]** `syscall_ret = 0x401410`  (remote arbitrary-read gadget farm)
11. **[✓ 됨]** Remote control-flow verified: RIP offset 88 and gadget farm prints Red Tide Terminal Revenge banner.
12. **[✓ 됨]** Working remote chain: leak stack with %7$p, compute buf=leak-0x60 and stack_stage=buf+0xa0, raw syscall read stage2 to stack_stage, return to stage2, ORW flag.txt.
13. **[✗ 배제]** BSS leave_ret pivot and read@plt staging — unreliable remotely; raw syscall read directly to stack_stage was verified.
14. **[🔎 정찰/맥락]** Flag recovered, not auto-submitted: grodno{6c6a7520-5c4c-48ef-b4c4-f876d6cf8a32}
15. **[🔎 정찰/맥락]** Reproducer: exploit_remote.py; remote entry used during solve: 10.112.0.12:48349.

## 검증된 오프셋/상수 (live 측정)
| key | value | src |
|---|---|---|
| `rip_offset` | `88` | remote write(1,banner) ROP verify |
| `stack_leak_fmt` | `%7$p` | remote audit-note format string |
| `stack_stage_delta` | `0xa0` | remote raw-syscall second read verified |
| `io_buf` | `0x4040a0` | remote writable buffer for ORW output |
| `pop_rdi` | `0x4013ec` | remote arbitrary-read gadget farm |
| `pop_rsi` | `0x4013f5` | remote arbitrary-read gadget farm |
| `pop_rdx` | `0x4013fe` | remote arbitrary-read gadget farm |
| `pop_rax` | `0x401407` | remote arbitrary-read gadget farm |
| `syscall_ret` | `0x401410` | remote arbitrary-read gadget farm |

## 배제된 것 (재시도 금지)
- ❌ BSS leave_ret pivot and read@plt staging — unreliable remotely; raw syscall read directly to stack_stage was verified.

## 재현
- 스크립트: `exploit_remote.py`
- 실행: `cd 95_Red_Tide_Terminal_Revenge && python3 exploit_remote.py`
