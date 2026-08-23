#!/usr/bin/env python3
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.backward_slice import _anchor_relation, _expr_uses, _stack_slot


class Arch:
    register_names = {16: "rax", 48: "rsp", 56: "rbp"}


class Con:
    def __init__(self, value): self.value = value


class Const:
    def __init__(self, value): self.con = Con(value)
    @property
    def child_expressions(self): return []


class Get:
    def __init__(self, offset): self.offset = offset
    @property
    def child_expressions(self): return []


class Binop:
    def __init__(self, op, left, right): self.op, self.args = op, [left, right]
    @property
    def child_expressions(self): return self.args


class Load:
    def __init__(self, addr): self.addr = addr
    @property
    def child_expressions(self): return [self.addr]


class RdTmp:
    def __init__(self, tmp): self.tmp = tmp
    @property
    def child_expressions(self): return []


class SliceHelperTests(unittest.TestCase):
    def test_direct_stack_slot(self):
        expr = Binop("Iop_Add64", Get(56), Const(0x20))
        self.assertEqual(_stack_slot(expr, Arch()), "rbp+32")
        expr = Binop("Iop_Sub64", Get(48), Const(0x18))
        self.assertEqual(_stack_slot(expr, Arch()), "rsp-24")

    def test_nested_stack_slot_accumulates_displacement(self):
        expr = Binop("Iop_Add64", Binop("Iop_Add64", Get(48), Const(0x20)), Const(8))
        self.assertEqual(_stack_slot(expr, Arch()), "rsp+40")
        expr = Binop("Iop_Sub64", Binop("Iop_Add64", Get(56), Const(0x20)), Const(8))
        self.assertEqual(_stack_slot(expr, Arch()), "rbp+24")

    def test_symbolic_or_two_stack_bases_are_not_guessed(self):
        self.assertIsNone(_stack_slot(Binop("Iop_Add64", Get(48), Get(16)), Arch()))
        self.assertIsNone(_stack_slot(Binop("Iop_Add64", Get(48), Get(56)), Arch()))

    def test_anchor_edge_polarity_is_explicit(self):
        self.assertEqual(_anchor_relation(0x401100, 0x401100), "taken")
        self.assertEqual(_anchor_relation(0x401200, 0x401100), "must-not-take")
        self.assertEqual(_anchor_relation(None, 0x401100), "must-not-take")

    def test_tmp_def_use_reaches_register(self):
        defs = {1: {"expr": Get(16), "insn": 0x401000, "stmt": 1}}
        regs, stack, trace = _expr_uses(RdTmp(1), Arch(), defs)
        self.assertEqual(regs, {"rax"})
        self.assertEqual(stack, set())
        self.assertTrue(any(x.get("kind") == "tmp" for x in trace))

    def test_load_reports_stack_and_base_register(self):
        expr = Load(Binop("Iop_Add64", Get(56), Const(8)))
        regs, stack, _ = _expr_uses(expr, Arch(), {})
        self.assertIn("rbp", regs)
        self.assertIn("rbp+8", stack)

    def test_unresolved_tmp_is_explicit(self):
        regs, stack, trace = _expr_uses(RdTmp(9), Arch(), {})
        self.assertFalse(regs)
        self.assertFalse(stack)
        self.assertEqual(trace[0]["kind"], "tmp-unresolved")


if __name__ == "__main__":
    unittest.main()
