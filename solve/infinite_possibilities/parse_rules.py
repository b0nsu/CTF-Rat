#!/usr/bin/env python3
from __future__ import annotations

import sys
from collections import Counter


def u16(buf: bytes, off: int) -> tuple[int, int]:
    return int.from_bytes(buf[off:off + 2], "big"), off + 2


def parse(path: str):
    data = open(path, "rb").read()
    assert data[:5] == b"RULES"
    count = int.from_bytes(data[8:12], "big")
    off = 12
    rules = {}
    order = []
    for _ in range(count):
        n, off = u16(data, off)
        name = data[off:off + n].decode()
        off += n
        ac, off = u16(data, off)
        alts = []
        for _ in range(ac):
            tc, off = u16(data, off)
            toks = []
            for _ in range(tc):
                typ = data[off]
                off += 1
                if typ == 1:
                    toks.append(("lit", chr(data[off])))
                    off += 1
                elif typ == 2:
                    rn, off = u16(data, off)
                    toks.append(("ref", data[off:off + rn].decode()))
                    off += rn
                else:
                    raise ValueError((off - 1, typ, name))
            alts.append(tuple(toks))
        mn, off = u16(data, off)
        msg = data[off:off + mn].decode(errors="replace")
        off += mn
        rules[name] = (alts, msg)
        order.append(name)
    if off != len(data):
        raise ValueError(f"trailing bytes: off={off} len={len(data)}")
    return rules, order


def main():
    rules, order = parse(sys.argv[1] if len(sys.argv) > 1 else "rules")
    print(f"rules={len(rules)} first={order[:3]} last={order[-10:]}")
    non_pat = [n for n in order if not n.startswith("pat_")]
    print("non_pat:", non_pat)
    for name in non_pat:
        alts, msg = rules[name]
        print(f"{name}: {len(alts)} alternatives msg={msg!r}")
        print("  sample:", alts[:5])
    refs = Counter()
    incoming = Counter()
    for name, (alts, msg) in rules.items():
        for alt in alts:
            for typ, val in alt:
                if typ == "ref":
                    refs[val] += 1
                    incoming[val] += 1
    missing = sorted(set(refs) - set(rules))
    roots = [n for n in order if incoming[n] == 0]
    print("missing refs:", missing[:20], "count", len(missing))
    print("roots count", len(roots), "sample", roots[:30], "last", roots[-30:])


if __name__ == "__main__":
    main()
