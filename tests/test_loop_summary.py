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
        self.assertIn("mod 2^32", by_target["rax"]["formula"])

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
