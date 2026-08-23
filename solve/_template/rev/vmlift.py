#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vmlift — custom-VM 리프터 스캐폴드 (rev 루프).

CTF rev 에서 자주 나오는 **커스텀 바이트코드 VM**(license_checker 류)을 만났을 때의
작업을 템플릿화한다. 빈 stub 이 아니라 **작동하는 toy-VM 레퍼런스 구현**(disasm +
emulate + oracle-brute)이다 — scout 는 이걸 복사해서 SPEC/handler 만 실 바이너리
의미로 갈아끼우면 된다.

┌─ 실 바이너리 적응 레시피 (license_checker 경험) ──────────────────────────────┐
│ 1. dispatch 루프 찾기:  revq <bin> --interesting / decomp <bin> <fn>            │
│      → opcode 바이트로 분기하는 큰 switch / 점프테이블(jmp [table + op*8]).      │
│ 2. opcode 인코딩 파악:  fetch 부에서 operand 폭 확인(1B op + 0~kB operand).      │
│ 3. 바이트코드 blob 위치:  전역 배열 or 데이터파일(예: pack.dat). revq --strings /│
│      objdump -s -j .rodata 로 덤프. 파일이면 그대로 로드.                        │
│ 4. opcode→의미 전사:  각 handler 를 decomp 로 읽어 아래 OP_* 에 옮긴다.          │
│ 5. 검증·역산:  disasm 으로 리스팅 sanity → emulate 로 정답입력=valid 확인 →     │
│      역산(아래 solve): (a) 입력이 바이트독립이면 per-byte brute(구현됨),          │
│      (b) 결합제약이면 emulate 를 oracle 로 angr/z3, (c) 단순하면 손으로.          │
└─────────────────────────────────────────────────────────────────────────────┘

사용:
  vmlift --disasm [BLOB]         # 바이트코드 → 리스팅 (없으면 내장 샘플)
  vmlift --run [BLOB] --input S  # 입력 S 로 실행 → valid/invalid
  vmlift --solve [BLOB]          # oracle-brute 로 accept 입력 복원
  vmlift selftest                # 내장 toy-VM 로 전 경로 검증 (angr/바이너리 불필요)

BLOB 미지정 시 내장 SAMPLE_BYTECODE 사용(문서·검증용).
"""
import argparse
import sys


# ══════════════════════════════════════════════════════════════════════════════
#  VM_SPEC — 실 바이너리에 맞춰 갈아끼우는 부분 (아래는 toy 레퍼런스)
#
#  각 opcode: (니모닉, operand 바이트 수).  handler 는 VM.step 안 dispatch 참조.
# ══════════════════════════════════════════════════════════════════════════════
OP_PUSH = 0x01   # PUSH imm   : operand 1B 를 스택에 push
OP_INP  = 0x02   # INP        : 다음 입력 바이트를 스택에 push
OP_XOR  = 0x03   # XOR        : pop b, pop a → push (a ^ b)
OP_ADD  = 0x04   # ADD        : pop b, pop a → push (a + b) & 0xff
OP_CMP  = 0x05   # CMP imm    : pop a; a==imm 이면 match++ 아니면 fail 기록
OP_HALT = 0xff   # HALT       : 종료

VM_SPEC = {
    OP_PUSH: ("PUSH", 1),
    OP_INP:  ("INP",  0),
    OP_XOR:  ("XOR",  0),
    OP_ADD:  ("ADD",  0),
    OP_CMP:  ("CMP",  1),
    OP_HALT: ("HALT", 0),
}

# toy 프로그램: 입력 4바이트 각각 XOR key 후 target 과 CMP.
#   key    = [0x10, 0x20, 0x30, 0x40]
#   accept = "ABCD" (0x41 42 43 44) → target = input^key = [0x51,0x62,0x73,0x04]
SAMPLE_BYTECODE = bytes([
    OP_INP, OP_PUSH, 0x10, OP_XOR, OP_CMP, 0x51,
    OP_INP, OP_PUSH, 0x20, OP_XOR, OP_CMP, 0x62,
    OP_INP, OP_PUSH, 0x30, OP_XOR, OP_CMP, 0x73,
    OP_INP, OP_PUSH, 0x40, OP_XOR, OP_CMP, 0x04,
    OP_HALT,
])
SAMPLE_INPUT_LEN = 4
SAMPLE_ALPHABET = range(0x20, 0x7f)   # printable


# ══════════════════════════════════════════════════════════════════════════════
#  disasm — 선형 스윕 (operand 폭은 VM_SPEC 기준). 실 VM 도 인코딩만 맞으면 재사용.
# ══════════════════════════════════════════════════════════════════════════════
def disasm(code, spec=VM_SPEC):
    out, pc = [], 0
    while pc < len(code):
        op = code[pc]
        name, nopnd = spec.get(op, ("DB?", 0))
        opnds = list(code[pc + 1: pc + 1 + nopnd])
        txt = name + ("".join(" 0x%02x" % o for o in opnds) if opnds else "")
        if op not in spec:
            txt = "DB 0x%02x  ; unknown opcode" % op
        out.append((pc, op, txt))
        pc += 1 + nopnd
    return out


def format_disasm(listing):
    return "\n".join("%04x: %-16s" % (pc, txt) for pc, _op, txt in listing)


# ══════════════════════════════════════════════════════════════════════════════
#  VM — emulator. 실 바이너리면 각 OP_* handler 를 decomp 의미로 옮긴다.
# ══════════════════════════════════════════════════════════════════════════════
class VMError(Exception):
    pass


class VM:
    def __init__(self, code, inp=b"", spec=VM_SPEC, max_steps=100000):
        self.code = code
        self.inp = inp
        self.spec = spec
        self.max_steps = max_steps
        self.reset()

    def reset(self):
        self.pc = 0
        self.stack = []
        self.iptr = 0          # 입력 포인터
        self.matches = 0       # CMP 성공 수
        self.checks = 0        # CMP 총 수
        self.halted = False

    def _pop(self):
        if not self.stack:
            raise VMError("stack underflow @%#x" % self.pc)
        return self.stack.pop()

    def step(self):
        op = self.code[self.pc]
        _name, nopnd = self.spec.get(op, (None, 0))
        opnd = self.code[self.pc + 1] if nopnd else None
        self.pc += 1 + nopnd

        if op == OP_PUSH:
            self.stack.append(opnd)
        elif op == OP_INP:
            b = self.inp[self.iptr] if self.iptr < len(self.inp) else 0
            self.iptr += 1
            self.stack.append(b)
        elif op == OP_XOR:
            b, a = self._pop(), self._pop()
            self.stack.append((a ^ b) & 0xFF)
        elif op == OP_ADD:
            b, a = self._pop(), self._pop()
            self.stack.append((a + b) & 0xFF)
        elif op == OP_CMP:
            a = self._pop()
            self.checks += 1
            if a == opnd:
                self.matches += 1
        elif op == OP_HALT:
            self.halted = True
        else:
            raise VMError("unknown opcode 0x%02x @%#x" % (op, self.pc - 1 - nopnd))

    def run(self):
        self.reset()
        steps = 0
        while not self.halted and self.pc < len(self.code):
            self.step()
            steps += 1
            if steps > self.max_steps:
                raise VMError("max_steps 초과 (무한루프?)")
        return self

    @property
    def valid(self):
        """accept 조건: 모든 CMP 통과. 실 VM 이면 여기 조건을 바꾼다."""
        return self.checks > 0 and self.matches == self.checks


# ══════════════════════════════════════════════════════════════════════════════
#  solve — VM 을 oracle 로 accept 입력 복원.
#    아래는 '입력 바이트 독립' 가정의 per-byte brute (matches 최대화).
#    결합 제약이면: emulate 를 제약함수로 z3, 또는 심볼릭이면 angr 로.
# ══════════════════════════════════════════════════════════════════════════════
def brute_solve(code, n, alphabet=SAMPLE_ALPHABET, spec=VM_SPEC):
    alphabet = list(alphabet)
    guess = bytearray([alphabet[0]] * n)
    for i in range(n):
        best_c, best_m = guess[i], -1
        for c in alphabet:
            guess[i] = c
            vm = VM(code, bytes(guess), spec).run()
            if vm.matches > best_m:
                best_m, best_c = vm.matches, c
        guess[i] = best_c
    sol = bytes(guess)
    ok = VM(code, sol, spec).run().valid
    return sol, ok


# ─────────────────────────── selftest (순수, angr/바이너리 무관) ───────────────────────────
def selftest():
    fails = []

    def chk(c, name):
        print(("  ✅ " if c else "  ❌ ") + name)
        if not c:
            fails.append(name)

    print("== vmlift selftest (내장 toy-VM) ==")

    lst = disasm(SAMPLE_BYTECODE)
    chk(lst[0][2] == "INP" and any("CMP 0x51" in t for _, _, t in lst), "disasm: INP/CMP 디코드")
    chk(len(lst) == 17, "disasm: 명령 수(4*(INP,PUSH,XOR,CMP) + HALT)")

    chk(VM(SAMPLE_BYTECODE, b"ABCD").run().valid, "emulate: 정답 'ABCD' → valid")
    wrong = VM(SAMPLE_BYTECODE, b"AAAA").run()
    chk(not wrong.valid and wrong.matches < wrong.checks, "emulate: 오답 → invalid")
    chk(VM(SAMPLE_BYTECODE, b"ABCD").run().matches == 4, "emulate: matches 카운트")

    sol, ok = brute_solve(SAMPLE_BYTECODE, SAMPLE_INPUT_LEN)
    chk(ok and sol == b"ABCD", "solve: oracle-brute 로 'ABCD' 복원")

    try:
        VM(bytes([0xAB]), b"").run()
        chk(False, "unknown opcode → VMError")
    except VMError:
        chk(True, "unknown opcode → VMError")

    print("-" * 40)
    if fails:
        print("FAIL %d: %s" % (len(fails), ", ".join(fails)))
        return 1
    print("ALL GREEN ✅")
    return 0


def _load_blob(path):
    if path is None:
        return SAMPLE_BYTECODE
    with open(path, "rb") as f:
        return f.read()


def build_parser():
    p = argparse.ArgumentParser(prog="vmlift", description="custom-VM 리프터 스캐폴드")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--disasm", nargs="?", const="__sample__", metavar="BLOB", help="바이트코드 디스어셈블")
    g.add_argument("--run", nargs="?", const="__sample__", metavar="BLOB", help="입력으로 실행")
    g.add_argument("--solve", nargs="?", const="__sample__", metavar="BLOB", help="accept 입력 복원")
    p.add_argument("--input", metavar="S", help="--run 입력 문자열")
    p.add_argument("--len", type=int, default=SAMPLE_INPUT_LEN, metavar="N", help="--solve 입력 길이")
    p.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    return p


def _resolve(v):
    return None if v == "__sample__" else v


def main(argv):
    if argv and argv[0] == "selftest":
        return selftest()
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()

    if args.disasm is not None:
        code = _load_blob(_resolve(args.disasm))
        print(format_disasm(disasm(code)))
    elif args.run is not None:
        code = _load_blob(_resolve(args.run))
        if args.input is None:
            print("[vmlift] --run 에는 --input 필요"); return 2
        vm = VM(code, args.input.encode()).run()
        print("input=%r → %s (matches %d/%d)"
              % (args.input, "VALID ✅" if vm.valid else "invalid", vm.matches, vm.checks))
    elif args.solve is not None:
        code = _load_blob(_resolve(args.solve))
        sol, ok = brute_solve(code, args.len)
        print("solved=%r (%s)  hex=%s" % (sol, "valid" if ok else "미검증", sol.hex()))
    else:
        build_parser().print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
