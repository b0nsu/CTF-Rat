#!/usr/bin/env python3
from __future__ import annotations

from functools import lru_cache

import z3
from parse_rules import parse


HEX = "0123456789abcdef"


def main():
    rules, _ = parse("rules")
    xs = [z3.Int(f"x{i}") for i in range(64)]
    s = z3.Solver()
    for x in xs:
        s.add(z3.And(x >= 0, x < 16))

    @lru_cache(maxsize=None)
    def match_rule(name: str, pos: int):
        alts, _msg = rules[name]
        return z3.Or(*[match_seq(alt, pos) for alt in alts])

    @lru_cache(maxsize=None)
    def match_seq(alt: tuple[tuple[str, str], ...], pos: int):
        conds = []
        p = pos
        for typ, val in alt:
            if typ == "lit":
                if p >= 64:
                    return z3.BoolVal(False)
                conds.append(xs[p] == HEX.index(val))
                p += 1
            else:
                if val == "any":
                    if p >= 64:
                        return z3.BoolVal(False)
                    p += 1
                else:
                    # All generated challenge rules are fixed-width; compute width separately.
                    w = width(val)
                    conds.append(match_rule(val, p))
                    p += w
        return z3.And(*conds) if p <= 64 else z3.BoolVal(False)

    @lru_cache(maxsize=None)
    def width(name: str) -> int:
        alts, _msg = rules[name]
        widths = set()
        for alt in alts:
            total = 0
            for typ, val in alt:
                total += 1 if typ == "lit" or val == "any" else width(val)
            widths.add(total)
        if len(widths) != 1:
            raise ValueError((name, sorted(widths)))
        return widths.pop()

    print("width(filter)=", width("filter"), "width(correct)=", width("correct"))
    s.add(z3.Not(match_rule("filter", 0)))
    assert s.check() == z3.sat
    m = s.model()
    ans = "".join(HEX[m[x].as_long()] for x in xs)
    print(ans)


if __name__ == "__main__":
    main()
