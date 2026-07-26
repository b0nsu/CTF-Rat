#!/usr/bin/env python3
import re
import subprocess
from collections import defaultdict
from pathlib import Path


BIN = Path("./main")
SIZE = 0x290


def disasm():
    return subprocess.check_output(
        ["objdump", "-d", "-Mintel", str(BIN)],
        text=True,
    ).splitlines()


def signed(v, bits):
    sign = 1 << (bits - 1)
    return v - (1 << bits) if v & sign else v


def recover(lines):
    pos = 0
    last_imm = None
    last_lea = None
    reads = {}
    constraints = []

    for line in lines:
        maddr = re.match(r"\s*([0-9a-f]+):", line)
        if not maddr:
            continue
        addr = int(maddr.group(1), 16)
        if not (0x12E3 <= addr <= 0x2AADC):
            continue

        m = re.search(r"mov\s+esi,0x([0-9a-f]+)", line)
        if m:
            last_imm = signed(int(m.group(1), 16), 32)

        m = re.search(r"mov\s+rsi,0x([0-9a-f]+)", line)
        if m:
            last_imm = signed(int(m.group(1), 16), 64)

        m = re.search(r"lea\s+rax,\[rbp-(0x[0-9a-f]+)\]", line)
        if m:
            last_lea = int(m.group(1), 16)

        if "call" in line and "<fseek@plt>" in line:
            pos += last_imm
            last_imm = None

        if "call" in line and "<fread@plt>" in line:
            reads[last_lea] = pos
            pos += 1
            last_lea = None

    last_stack = None
    for line in lines:
        maddr = re.match(r"\s*([0-9a-f]+):", line)
        if not maddr:
            continue
        addr = int(maddr.group(1), 16)
        if not (0x12E3 <= addr <= 0x2AADC):
            continue

        m = re.search(r"movzx\s+eax,BYTE PTR \[rbp-(0x[0-9a-f]+)\]", line)
        if m:
            last_stack = int(m.group(1), 16)

        m = re.search(r"cmp\s+al,0x([0-9a-f]+)", line)
        if m and last_stack is not None:
            constraints.append((reads[last_stack], int(m.group(1), 16)))
            last_stack = None

    by_pos = defaultdict(set)
    for file_pos, byte in constraints:
        by_pos[file_pos].add(byte)

    conflicts = {k: v for k, v in by_pos.items() if len(v) != 1}
    if conflicts:
        raise SystemExit(f"conflicting constraints: {conflicts}")
    if set(by_pos) != set(range(SIZE)):
        missing = sorted(set(range(SIZE)) - set(by_pos))
        raise SystemExit(f"missing offsets: {missing[:10]}")

    return bytes(next(iter(by_pos[i])) for i in range(SIZE))


if __name__ == "__main__":
    data = recover(disasm())
    Path("answer.txt").write_bytes(data)
    print(data.decode())
