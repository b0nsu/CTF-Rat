---
title: "kidheap"
ctf: "DreamHack"
date: 2026-07-15
category: pwn
difficulty: hard
points: unknown
flag_format: "DH{...}"
author: "taeeun"
---

# kidheap

## Summary

`kidheap` is a glibc 2.35 heap note challenge. The delete routine toggles a deleted flag even when a note is already deleted, which re-enables a stale note pointer without freeing it again. That gives UAF read/write on freed chunks, enough for libc/heap leaks, tcache poisoning, and a House of Apple 2 FSOP chain through `_IO_list_all`.

## Solution

### Step 1: Find the UAF

The program stores up to 16 notes. Each note has:

- `size` at `+0x00`
- `idx` at `+0x08`
- `name` pointer at `+0x10`
- `content` pointer at `+0x18`

`create` bounds-checks the index, allocates a 0x20 note object, a user-sized `name`, and a fixed 0x100 `content`.

`delete` frees `content`, `name`, and the note object when the deleted flag is 0, but it always writes:

```c
deleted[idx] = (deleted[idx] == 0);
```

So calling `delete(idx)` twice does not double-free; it toggles the deleted flag back to 0 and leaves the stale note pointer usable. `print` and `edit` then operate on freed chunks.

### Step 2: Leak libc and heap

The exploit allocates 8 notes, then frees all of them. The seven 0x110 content chunks fill tcache, and the eighth content chunk goes to unsorted bin. After toggling note 7 back to active, `print(7)` leaks the unsorted-bin fd pointer.

For Ubuntu 22.04 glibc 2.35 in the provided Docker image:

```text
unsorted leak offset = 0x21ace0
```

Then toggling note 0 back to active and printing its freed tcache chunk leaks a safe-linking encoded NULL, which is just:

```text
heap_key = chunk_addr >> 12
heap_base_page = heap_key << 12
```

The allocation layout is stable, so the exploit uses fixed offsets from the heap page:

```text
content4  = heap_base_page + 0x850
wide_data = heap_base_page + 0x9b0
fake FILE = heap_base_page + 0xb10
```

### Step 3: Tcache poison `_IO_list_all`

The final chain is House of Apple 2:

1. Place fake `_IO_FILE` in the freed content6 chunk.
2. Place fake wide data and fake wide vtable in the freed content5 chunk.
3. Poison the 0x110 tcache fd in content4 with:

```python
encoded = target ^ (content4 >> 12)
target = libc.sym["_IO_list_all"]
```

4. Allocate again so the next 0x110 `name` allocation returns `_IO_list_all`.
5. Write `_IO_list_all = fake_file`.
6. Choose menu option 5 to call `exit()`, triggering `_IO_flush_all_lockp`.

The fake FILE starts with a shell command, so the Apple2 path eventually calls:

```text
system(" sh -c 'cat flag /f* 2>&1'")
```

## Exploit

Complete exploit:

```bash
./solve.py REMOTE RECVALL
```

Local Docker verification:

```bash
docker build -t kidheap-local .
./solve.py DOCKER RECVALL
```

The script is in:

```text
solve_incoming/kidheap/solve.py
```

Important runtime options:

- `REMOTE`: connect to `host3.dreamhack.games:20427`
- `DOCKER`: run the provided challenge image locally
- `RECVALL`: receive raw command output after `exit()`
- `ECHO`: use `echo PWNED` instead of reading the flag, useful for checking command execution

## Verification

Local Docker output:

```text
DH{**flag**}
cat: '/f*': No such file or directory
```

Remote output:

```text
DH{8d35746cd5b310eb65dcfeed2e05188b5db616378073efd91fd2f6204a34bf48:82OOP40P4WtVDnGX1RLaBg==}
cat: '/f*': No such file or directory
```

## Flag

```text
DH{8d35746cd5b310eb65dcfeed2e05188b5db616378073efd91fd2f6204a34bf48:82OOP40P4WtVDnGX1RLaBg==}
```
