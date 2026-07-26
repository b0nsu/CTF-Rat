# pwnable-rootkit — SOLVED ✅

> 팀 공유용 writeup. **풀이과정(어떻게 도달했나) 포함.**

## 풀이과정 (진행 순서 — 시도·배제·핵심착상)
1. **[🔎 정찰/맥락]** pwnable.kr rootkit selected: Grotesque unsolved for account ssttff; target ssh rootkit@pwnable.kr -p2222 pw guest
2. **[✓ 됨]** Logged into rootkit QEMU console; /flag exists inode=13 size=46 but open/cat/dd /flag returns EPERM and kernel logs You will not see the flag...
3. **[? 가설]** rootkit.ko hooks sys_open/openat/link/symlink/rename and blocks path strings containing flag; raw block device path /dev/ram0 should bypass pathname filter
4. **[📏 측정]** `ext2_block_size = 1024`  (stat /flag IO Block and ext2 superblock)
5. **[📏 측정]** `flag_inode = 13`  (ls -li /flag)
6. **[📏 측정]** `inode_table_block = 20`  (ext2 group descriptor bg_inode_table)
7. **[📏 측정]** `flag_direct_block = 3586`  (inode 13 direct block[0] from /dev/ram0)
8. **[🧪 primitive]** `raw_ext2_read` = **PASS** — remote rootkit QEMU: /flag open blocked, but /dev/ram0 raw read at block 3586 offset 3672064 count 46 yields gzip stream; gzip -dc returns R0otK1tty_Swe3ty_KittY
9. **[✓ 됨]** solve.py fresh remote verification prints R0otK1tty_Swe3ty_KittY
10. **[→ 다음]** Human submit flag to pwnable.kr; auto-submit intentionally skipped per honest-mode

## Gate Status
- Primitive: PASS
  - `raw_ext2_read`: remote rootkit QEMU: /flag open blocked, but /dev/ram0 raw read at block 3586 offset 3672064 count 46 yields gzip stream; gzip -dc returns R0otK1tty_Swe3ty_KittY
- Active hypotheses:
  - rootkit.ko hooks sys_open/openat/link/symlink/rename and blocks path strings containing flag; raw block device path /dev/ram0 should bypass pathname filter

## 검증된 오프셋/상수 (live 측정)
| key | value | src |
|---|---|---|
| `ext2_block_size` | `1024` | stat /flag IO Block and ext2 superblock |
| `flag_inode` | `13` | ls -li /flag |
| `inode_table_block` | `20` | ext2 group descriptor bg_inode_table |
| `flag_direct_block` | `3586` | inode 13 direct block[0] from /dev/ram0 |

## 재현
- 스크립트: `solve.py`
- 실행: `cd pwnable-rootkit && python3 solve.py`
