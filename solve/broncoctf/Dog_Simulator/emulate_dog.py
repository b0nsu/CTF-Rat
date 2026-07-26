#!/usr/bin/env python3
from itertools import permutations
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM
from unicorn.arm64_const import *

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "solve_incoming/broncoctf/46_Dog_Simulator/dog-sim-mac"
BASE = 0x100000000
MAIN = 0x100000500
RET = 0x100001310
STACK = 0x700000000
HOOK_BASE = 0x200000000
RUNE = 0x300000000
STDINP = 0x300010000
STDOUTP = 0x300010100
GUARDP = 0x300010200

STUBS = {
    0x100001390: "__maskrune",
    0x10000139c: "__stack_chk_fail",
    0x1000013a8: "__tolower",
    0x1000013b4: "atoi",
    0x1000013c0: "clearerr",
    0x1000013cc: "fflush",
    0x1000013d8: "fgets",
    0x1000013e4: "printf",
    0x1000013f0: "putchar",
    0x1000013fc: "puts",
    0x100001408: "snprintf",
    0x100001414: "strlen",
}


def cstr(mu, addr):
    if addr >= 0x1000000000000:
        addr = BASE + (addr & 0xffffffff)
    out = bytearray()
    while True:
        b = mu.mem_read(addr, 1)[0]
        if b == 0:
            return bytes(out)
        out.append(b)
        addr += 1


def w64(mu, addr, val):
    mu.mem_write(addr, int(val).to_bytes(8, "little"))


def run(inputs):
    data = BIN.read_bytes()
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(BASE, 0x5000)
    for paddr, vaddr, size in [
        (0x500, 0x100000500, 0xe90),
        (0x1390, 0x100001390, 0x90),
        (0x1420, 0x100001420, 0x1f8),
        (0x1618, 0x100001618, 0x6ad),
        (0x4000, 0x100004000, 0x80),
        (0x4080, 0x100004080, 0x70),
    ]:
        mu.mem_write(vaddr, data[paddr:paddr + size])

    mu.mem_map(STACK, 0x100000)
    mu.mem_map(RUNE, 0x20000)
    mu.mem_map(HOOK_BASE, 0x1000)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x80000)

    # Imported data pointers.
    w64(mu, 0x100004000, RUNE)
    w64(mu, 0x100004018, GUARDP)
    w64(mu, 0x100004020, STDINP)
    w64(mu, 0x100004028, STDOUTP)
    w64(mu, GUARDP, 0x4142434445464748)

    # Minimal Darwin rune table for the program's ASCII alphabetic test.
    for c in list(range(ord("A"), ord("Z") + 1)) + list(range(ord("a"), ord("z") + 1)):
        mu.mem_write(RUNE + 0x3c + c * 4, (0x100).to_bytes(4, "little"))

    q = [x if x.endswith(b"\n") else x + b"\n" for x in inputs]
    output = []

    def ret(x0=0):
        mu.reg_write(UC_ARM64_REG_X0, x0 & ((1 << 64) - 1))
        mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_X30))

    def hook_code(mu, addr, size, _):
        if addr == RET:
            raise StopIteration
        name = STUBS.get(addr)
        if not name:
            return
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        if name == "fgets":
            if not q:
                ret(0)
                return
            s = q.pop(0)[: max(0, x1 - 1)] + b"\0"
            mu.mem_write(x0, s)
            ret(x0)
        elif name == "strlen":
            ret(len(cstr(mu, x0)))
        elif name == "atoi":
            bs = cstr(mu, x0).strip()
            try:
                ret(int(bs.split()[:1][0]))
            except Exception:
                ret(0)
        elif name == "snprintf":
            fmt = cstr(mu, x2)
            if b"%s" in fmt:
                src_addr = mu.reg_read(UC_ARM64_REG_X3)
                try:
                    src = cstr(mu, src_addr)
                except Exception:
                    sp = mu.reg_read(UC_ARM64_REG_SP)
                    src_addr = int.from_bytes(mu.mem_read(sp, 8), "little")
                    src = cstr(mu, src_addr)
                rendered = fmt.replace(b"%s", src)
            else:
                rendered = fmt
            mu.mem_write(x0, rendered[: max(0, x1 - 1)] + b"\0")
            ret(len(rendered))
        elif name in ("puts", "printf"):
            try:
                output.append(cstr(mu, x0))
            except Exception:
                output.append(f"<{name} unmapped {x0:#x}>".encode())
            ret(0)
        elif name == "putchar":
            output.append(bytes([x0 & 0xff]))
            ret(x0 & 0xff)
        elif name == "__tolower":
            c = x0 & 0xff
            ret(ord(chr(c).lower()) if 65 <= c <= 90 else c)
        elif name == "__maskrune":
            c = x0 & 0xff
            ret(0x100 if (65 <= c <= 90 or 97 <= c <= 122) else 0)
        elif name in ("fflush", "clearerr"):
            ret(0)
        else:
            raise RuntimeError(name)

    mu.hook_add(UC_HOOK_CODE, hook_code)
    try:
        mu.emu_start(MAIN, 0)
    except StopIteration:
        pass
    return b"\n".join(output).decode("latin1", "replace")


def main():
    word_orders = [
        [b"rjeeqwm", b"lhfzzflsyciu"],
        [b"lhfzzflsyciu", b"rjeeqwm"],
        [b"gremlin", b"lhfzzflsyciu"],
        [b"lhfzzflsyciu", b"gremlin"],
    ]
    for acts in sorted(set(permutations([b"1", b"2", b"3", b"4", b"6", b"6"]))):
        for word_order in word_orders:
            wi = 0
            inp = [b""]
            for a in acts:
                inp.append(a)
                if a == b"6":
                    inp.append(word_order[wi])
                    wi += 1
            out = run(inp)
            if "awww he said" in out:
                print("actions:", b" ".join(acts).decode())
                print("words:", [w.decode() for w in word_order])
                print(out.split("=== Finale ===", 1)[-1].strip())
                return
    raise SystemExit("no solution")


if __name__ == "__main__":
    main()
