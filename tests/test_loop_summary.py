import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
from ratlib.loop_summary import normalize_register, parse_affine_update, summarize_instruction_stream


class _Insn:
    def __init__(self, mnemonic, op_str, writes=(), address=0x401000):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.address = address
        self.insn = self
        self._writes = list(writes)

    def regs_access(self):
        return [], self._writes

    def reg_name(self, reg):
        return reg


class LoopSummaryUnit(unittest.TestCase):
    def test_register_aliases_are_canonical(self):
        self.assertEqual(normalize_register("eax"), "rax")
        self.assertEqual(normalize_register("r8d"), "r8")
        self.assertEqual(normalize_register("ecx"), "rcx")

    def test_affine_immediate_updates(self):
        self.assertEqual(parse_affine_update("add", "eax, 8"), ("rax", 8))
        self.assertEqual(parse_affine_update("sub", "r8d, 0x10"), ("r8", -16))
        self.assertEqual(parse_affine_update("inc", "ecx"), ("rcx", 1))
        self.assertEqual(parse_affine_update("dec", "r9"), ("r9", -1))
        self.assertIsNone(parse_affine_update("add", "eax, ecx"))

    def test_straight_line_affine_loop_gets_candidate(self):
        out = summarize_instruction_stream([
            _Insn("add", "eax, 8", writes=("eax",)),
            _Insn("inc", "ecx", writes=("ecx",)),
            _Insn("cmp", "ecx, 100", writes=()),
            _Insn("jne", "0x401000", writes=()),
        ], bit_width=32)
        by_target = {r["target"]: r for r in out["recurrences"]}
        self.assertEqual(by_target["rax"]["delta"], 8)
        self.assertEqual(by_target["rcx"]["delta"], 1)
        self.assertEqual(by_target["rax"]["register_family"], "rax")
        self.assertEqual(by_target["rax"]["write_semantics"], "full-width")
        self.assertIn("mod 2^32", by_target["rax"]["formula"])

    def test_amd64_eax_update_is_32bit_zero_extending_recurrence(self):
        out = summarize_instruction_stream([
            _Insn("add", "eax, 8", writes=("eax",)),
            _Insn("cmp", "eax, 100", writes=()),
            _Insn("jne", "0x401000", writes=()),
        ], bit_width=64)
        self.assertEqual(len(out["recurrences"]), 1)
        recurrence = out["recurrences"][0]
        self.assertEqual(recurrence["target"], "eax")
        self.assertEqual(recurrence["register_family"], "rax")
        self.assertEqual(recurrence["bit_width"], 32)
        self.assertEqual(recurrence["write_semantics"], "zero-extend-to-64")
        self.assertIn("mod 2^32", recurrence["formula"])
        self.assertIn("zero-extends into rax", recurrence["formula"])

    def test_amd64_partial_register_write_is_rejected(self):
        for operand in ("ax", "al"):
            with self.subTest(operand=operand):
                out = summarize_instruction_stream([
                    _Insn("add", "%s, 1" % operand, writes=(operand,)),
                ], bit_width=64)
                self.assertEqual(out["recurrences"], [])
                self.assertIn("partial_register_write", out["unsupported"])
                self.assertIn("no_affine_register_recurrence", out["unsupported"])

    def test_mixed_eax_and_rax_updates_do_not_get_merged(self):
        out = summarize_instruction_stream([
            _Insn("add", "eax, 1", writes=("eax",)),
            _Insn("add", "rax, 1", writes=("rax",)),
        ], bit_width=64)
        self.assertEqual(out["recurrences"], [])
        self.assertIn("mixed_register_width", out["unsupported"])

    def test_clobber_prevents_false_recurrence(self):
        out = summarize_instruction_stream([
            _Insn("add", "eax, 8", writes=("eax",)),
            _Insn("mov", "eax, edx", writes=("eax",)),
        ], bit_width=32)
        self.assertEqual(out["recurrences"], [])
        self.assertIn("no_affine_register_recurrence", out["unsupported"])

    def test_branch_or_call_disables_recurrence(self):
        branched = summarize_instruction_stream([_Insn("inc", "ecx", writes=("ecx",))], internal_branch=True)
        self.assertEqual(branched["recurrences"], [])
        self.assertIn("internal_branch", branched["unsupported"])
        called = summarize_instruction_stream([
            _Insn("inc", "ecx", writes=("ecx",)),
            _Insn("call", "0x402000", writes=()),
        ])
        self.assertEqual(called["recurrences"], [])
        self.assertIn("call_in_loop", called["unsupported"])

    def test_incomplete_write_set_suppresses_candidate(self):
        out = summarize_instruction_stream([
            _Insn("add", "eax, 8", writes=("eax",)),
            _Insn("mov", "eax, edx", writes=()),
        ], bit_width=32)
        self.assertEqual(out["recurrences"], [])
        self.assertFalse(out["register_write_set_complete"])
        self.assertIn("register_write_set_incomplete", out["unsupported"])

    def test_memory_write_is_reported_not_hidden(self):
        out = summarize_instruction_stream([
            _Insn("add", "eax, 1", writes=("eax",)),
            _Insn("mov", "dword ptr [rbp-4], eax", writes=()),
        ])
        self.assertEqual(out["memory_writes"], 1)
        self.assertIn("memory_state_unmodeled", out["unsupported"])


if __name__ == "__main__":
    unittest.main()
