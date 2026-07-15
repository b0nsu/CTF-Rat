# kidheap state

## Target

- Challenge: `kidheap`
- Category: pwn / heap
- Local binary: `solve_incoming/kidheap/deploy/prob`
- Remote: `host3.dreamhack.games:20427`
- Docker base: `ubuntu:22.04@sha256:340d9b015b194dc6e2a13938944e0d016e57b9679963fdeb9ce021daac430221`
- Verified glibc from built image: `2.35-0ubuntu3.8`

## Static triage

- Protections: Full RELRO, Canary, NX, PIE.
- Imports: `malloc`, `free`, `read`, `printf`, `puts`, `atoi`, `strtoull`, `exit`.
- Menu:
  - `1. create note`
  - `2. delete note`
  - `3. edit note`
  - `4. print note`
  - `5. exit`
- Note layout:
  - `+0x00`: name size
  - `+0x08`: index
  - `+0x10`: name pointer
  - `+0x18`: content pointer
- Globals:
  - `notes[16]` around PIE offset `0x4060`
  - `deleted[16]` around PIE offset `0x40e0`
  - `name_sizes[16]` around PIE offset `0x4120`

## Vulnerability

- `create` checks index range `0 <= idx <= 15`.
- `delete`, `edit`, and `print` do not call the index bounds helper.
- Main exploitable bug is in `delete`:
  - First delete frees `content`, `name`, and the note object.
  - Second delete sees `deleted[idx] != 0`, prints an error, but still toggles `deleted[idx]` back to 0.
  - The note pointer is never cleared.
- Result: call `delete(idx)` twice to reactivate a freed note object, then use `print` and `edit` as UAF primitives.

## Confirmed primitives

- `delete(i); delete(i); print(i)` leaks freed chunk contents through `%s`.
- Freeing 8 content chunks of size 0x110 puts 7 in tcache and 1 in unsorted bin.
- Reactivating note 7 leaks an unsorted-bin pointer from its stale content pointer.
- Reactivating note 0 leaks a safe-linking encoded NULL from a freed tcache chunk, giving `heap_key = chunk >> 12`.
- `edit` on a reactivated stale note gives write access to freed `name` and `content` chunks.

## Offsets

- Ubuntu 22.04 glibc 2.35 candidate used for final solve:
  - unsorted leak offset: `0x21ace0`
  - `system`: `0x50d70`
  - `_IO_list_all`: `0x21b680`
  - `_IO_wfile_jumps`: `0x2170c0`
- Initial jammy libc was checked as a fallback:
  - unsorted leak offset: `0x219ce0`
  - `system`: `0x50d60`
  - `_IO_list_all`: `0x21a680`
  - `_IO_wfile_jumps`: `0x2160c0`
- Host glibc 2.39 was checked only as a negative/fallback candidate:
  - unsorted leak offset: `0x203b20`

## Heap layout used

After creating 8 notes with name size `0x18` and freeing all 8, the 0x110 content chunks have stable offsets from the heap page:

- `content0 = heap_page + 0x2d0`
- `content4 = heap_page + 0x850`
- `content5 = heap_page + 0x9b0`
- `content6 = heap_page + 0xb10`

Originally I tried recovering `content4/content5/content6` from tcache fd leaks, but `%s` leaks can truncate on NUL bytes. The final exploit uses the stable heap-page offsets instead.

## Exploit chain

1. Allocate 8 notes.
2. Free all 8 notes.
3. Toggle note 7 back active and leak unsorted-bin fd from its freed content chunk.
4. Compute libc base with `leak - 0x21ace0`.
5. Toggle note 0 back active and leak `heap_key`.
6. Compute heap page and stable content chunk addresses.
7. Toggle/create to allocate fake wide data in content5 and fake FILE in content6.
8. Toggle note 4 back active and overwrite its freed 0x110 tcache fd with safe-linked `_IO_list_all`.
9. Allocate a 0x110 name chunk overlapping `_IO_list_all`.
10. Write `_IO_list_all = fake_file`.
11. Choose menu `5` to call `exit()`.
12. `_IO_flush_all_lockp` follows the fake FILE / wide-data path and calls `system`.

## Verification log

- Local Docker direct run: `./solve.py DOCKER RECVALL`
  - Output included `DH{**flag**}`.
- Local Docker socat run on `127.0.0.1:18080`: `./solve.py LOCALNET ECHO RECVALL`
  - Output included `PWNED`.
- Remote echo probe: `./solve.py REMOTE ECHO RECVALL`
  - Output included `PWNED`.
- Remote final: `./solve.py REMOTE RECVALL`
  - Output included the real flag.

## Flag

```text
DH{8d35746cd5b310eb65dcfeed2e05188b5db616378073efd91fd2f6204a34bf48:82OOP40P4WtVDnGX1RLaBg==}
```
