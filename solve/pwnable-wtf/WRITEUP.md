# pwnable-wtf — SOLVED ✅

> 팀 공유용 writeup. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[🔎 정찰/맥락]** pwnable.kr wtf selected: Grotesque unsolved for ssttff; target ssh wtf@pwnable.kr -p2222 pw guest; wrapper says nc 0 10039 and expects hex payload
2. **[? 가설]** scanf("%d") accepts -1 and stdio prebuffers 4096 bytes; put real overflow stage after byte 4096 so my_fgets raw read receives it
3. **[📏 측정]** `stdio_prefetch = 4096`  (strace read(0, ..., 4096) by scanf before my_fgets raw read)
4. **[📏 측정]** `ret2main_ret = 56`  (local sweep: prefix 4096 then stage offset 56 controls main return)
5. **[📏 측정]** `ret_gadget = 0x400668`  (single ret for system stack alignment)
6. **[📏 측정]** `win = 0x4005f4`  (symbol table win calls system("/bin/cat flag"))
7. **[🧪 primitive]** `ret2win_prefetch` = **PASS** — local: payload -1 + 4093 pad + A*56 + ret(0x400668)+win(0x4005f4) prints LOCAL_WTF_FLAG
8. **[✓ 됨]** remote pwnable.kr:10039 fresh solve.py prints LIBC_buff3ring_dr1ves_m3_cr4zy
9. **[→ 다음]** Human submit flag to pwnable.kr; auto-submit intentionally skipped per honest-mode
10. **[✓ 됨]** flag LIBC_buff3ring_dr1ves_m3_cr4zy verified from remote pwnable.kr:10039 via solve.py; not submitted automatically

## Gate Status
- Primitive: PASS
  - `ret2win_prefetch`: local: payload -1 + 4093 pad + A*56 + ret(0x400668)+win(0x4005f4) prints LOCAL_WTF_FLAG
- Active hypotheses:
  - scanf("%d") accepts -1 and stdio prebuffers 4096 bytes; put real overflow stage after byte 4096 so my_fgets raw read receives it

## 검증된 오프셋/상수 (live 측정)
| key | value | src |
|---|---|---|
| `stdio_prefetch` | `4096` | strace read(0, ..., 4096) by scanf before my_fgets raw read |
| `ret2main_ret` | `56` | local sweep: prefix 4096 then stage offset 56 controls main return |
| `ret_gadget` | `0x400668` | single ret for system stack alignment |
| `win` | `0x4005f4` | symbol table win calls system("/bin/cat flag") |

## 재현
- 스크립트: `solve.py`
- 실행: `cd pwnable-wtf && python3 solve.py`
