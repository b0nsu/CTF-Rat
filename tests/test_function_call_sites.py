import importlib.machinery
import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))


def load_revq():
    path = ROOT / "bin" / "revq"
    loader = importlib.machinery.SourceFileLoader("_test_call_sites_revq", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


REVQ = load_revq()


class _Insn:
    def __init__(self, address, mnemonic="nop", op_str="", writes=(), operand_type=None, semantic=True):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self._writes = tuple(writes)
        self.operands = ([] if operand_type is None else
                         [type("Operand", (), {"type": operand_type})()])
        self._semantic = semantic

    def regs_access(self):
        if not self._semantic:
            raise RuntimeError("instruction detail unavailable")
        return (), self._writes

    def reg_name(self, register):
        return register


class _Block:
    def __init__(self, addresses, jumpkind="Ijk_Call", insns=None):
        self.capstone = type("Capstone", (), {"insns": insns or [_Insn(x) for x in addresses]})()
        self.vex = type("Vex", (), {"jumpkind": jumpkind})()


class _Function:
    def get_call_sites(self):
        return [0x401100, 0x401120]

    def get_call_target(self, site):
        return 0x401030


class FunctionCallSiteTests(unittest.TestCase):
    def test_preserves_repeated_api_calls_and_instruction_addresses(self):
        blocks = {0x401100: _Block([0x401100, 0x40110B]),
                  0x401120: _Block([0x401120, 0x40112D])}
        factory = type("Factory", (), {"block": lambda _self, addr: blocks[addr]})()
        project = type("Project", (), {"factory": factory})()
        callee = type("Callee", (), {"name": "memcmp"})()
        sites = REVQ._func_call_sites(project, _Function(), {0x401030: callee}, "AMD64", "elf")

        self.assertEqual([x["api"] for x in sites], ["memcmp", "memcmp"])
        self.assertEqual([x["block_address"] for x in sites], [0x401100, 0x401120])
        self.assertEqual([x["instruction_address"] for x in sites], [0x40110B, 0x40112D])
        self.assertTrue(all(x["analysis_source"] == "angr.CFGFast" for x in sites))
        self.assertTrue(all(x["address_space"] == "loader-virtual-address" for x in sites))

        rev = {
            "schema": REVQ.SCHEMA, "engine": "angr", "bin": "fixture", "functions": [
                {"name": "check", "addr": 0x401100, "size": 64, "calls": ["memcmp"],
                 "call_sites": sites, "strings": [], "nblocks": 2, "ninstr": 8}
            ], "strings": [],
        }
        card = REVQ.compute_function_card(rev, "check")
        self.assertEqual([x["address"] for x in card["facts"]["compare_sites"]],
                         [0x40110B, 0x40112D])

    def test_decode_failure_is_explicit(self):
        factory = type("Factory", (), {"block": lambda _self, _addr: _Block([], "Ijk_Boring")})()
        project = type("Project", (), {"factory": factory})()
        callee = type("Callee", (), {"name": "memcmp"})()
        sites = REVQ._func_call_sites(project, _Function(), {0x401030: callee}, "AMD64", "elf")
        self.assertTrue(all(x["instruction_address"] is None for x in sites))
        self.assertTrue(all(x.get("unresolved_reason") for x in sites))

    def test_length_constant_requires_last_rdx_definition_to_be_literal(self):
        literal = [_Insn(0x401100, "mov", "edx, 0x20", ("edx",)), _Insn(0x401105, "call", "0x401030")]
        overwritten = [_Insn(0x401120, "mov", "edx, 4", ("edx",)), _Insn(0x401125, "mov", "rdx, rax", ("rdx",)),
                       _Insn(0x401128, "call", "0x401030")]
        self.assertEqual(REVQ._x86_64_length_argument(literal, "memcmp")["value"], 0x20)
        result = REVQ._x86_64_length_argument(overwritten, "memcmp")
        self.assertEqual(result["status"], "value_unresolved")
        self.assertEqual(result["evidence"]["instruction_address"], 0x401125)

    def test_length_states_distinguish_absent_value_and_abi(self):
        call = [_Insn(0x401100, "call", "0x401030")]
        self.assertEqual(REVQ._x86_64_length_argument(call, "strcmp")["status"], "not_applicable")
        self.assertEqual(REVQ._x86_64_length_argument(call, "memcmp")["status"], "value_unresolved")
        self.assertEqual(REVQ._x86_64_length_argument(call, "memcmp", False)["status"], "unsupported_abi")
        partial_write = [_Insn(0x4010F0, "mov", "edx, 4", ("edx",)), _Insn(0x401100, "mov", "dl, 7", ("dl",)),
                         _Insn(0x401105, "call", "0x401030")]
        self.assertEqual(REVQ._x86_64_length_argument(partial_write, "memcmp")["status"], "value_unresolved")

    def test_implicit_writes_invalidate_an_earlier_literal_but_reads_do_not(self):
        for mnemonic in ("cqo", "mul", "div"):
            insns = [_Insn(0x401000, "mov", "edx, 32", ("edx",)),
                     _Insn(0x401004, mnemonic, "rcx" if mnemonic != "cqo" else "", ("rdx",)),
                     _Insn(0x401008, "call", "0x401030")]
            self.assertEqual(REVQ._x86_64_length_argument(insns, "memcmp")["status"],
                             "value_unresolved", mnemonic)
        reads_rdx = [_Insn(0x401000, "mov", "edx, 32", ("edx",)),
                     _Insn(0x401004, "cmp", "rdx, rax", ()),
                     _Insn(0x401008, "call", "0x401030")]
        self.assertEqual(REVQ._x86_64_length_argument(reads_rdx, "memcmp")["value"], 32)

    def test_missing_register_semantics_is_unresolved(self):
        insns = [_Insn(0x401000, "mov", "edx, 32", semantic=False),
                 _Insn(0x401008, "call", "0x401030")]
        self.assertEqual(REVQ._x86_64_length_argument(insns, "memcmp")["status"],
                         "value_unresolved")

    def test_direct_call_requires_immediate_operand_type(self):
        self.assertTrue(REVQ._is_immediate_call(_Insn(0, "call", "0x401030", operand_type=2)))
        self.assertFalse(REVQ._is_immediate_call(_Insn(0, "call", "r8", operand_type=1)))
        self.assertFalse(REVQ._is_immediate_call(_Insn(0, "call", "qword ptr [rax]", operand_type=3)))


@unittest.skipUnless(importlib.util.find_spec("capstone"), "capstone unavailable")
class CapstoneInstructionSemanticsTests(unittest.TestCase):
    @staticmethod
    def decode(blob):
        import capstone
        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        engine.detail = True
        return list(engine.disasm(blob, 0x401000))

    def test_real_bytes_cover_implicit_writes_reads_and_call_operand_types(self):
        call = b"\xe8\x00\x00\x00\x00"
        for effect in (b"\x48\x99", b"\x48\xf7\xe1", b"\x48\xf7\xf1"):  # cqo, mul rcx, div rcx
            insns = self.decode(b"\xba\x20\x00\x00\x00" + effect + call)
            self.assertEqual(REVQ._x86_64_length_argument(insns, "memcmp")["status"],
                             "value_unresolved")
        reads_only = self.decode(b"\xba\x20\x00\x00\x00\x48\x39\xc2" + call)  # cmp rdx, rax
        self.assertEqual(REVQ._x86_64_length_argument(reads_only, "memcmp")["value"], 32)
        self.assertTrue(REVQ._is_immediate_call(self.decode(call)[0]))
        self.assertFalse(REVQ._is_immediate_call(self.decode(b"\x41\xff\xd0")[0]))  # call r8
        self.assertFalse(REVQ._is_immediate_call(self.decode(b"\xff\x10")[0]))      # call [rax]


@unittest.skipUnless(shutil.which("cc") and shutil.which("objdump"), "compiler/objdump unavailable")
class AngrCallSiteIntegrationTests(unittest.TestCase):
    def test_angr_addresses_match_independent_objdump(self):
        try:
            import angr  # noqa: F401
        except ImportError:
            self.skipTest("angr unavailable")
        with tempfile.TemporaryDirectory() as tempdir:
            binary = pathlib.Path(tempdir) / "callsites"
            source = ROOT / "tests" / "fixtures" / "analysis" / "callsites.c"
            built = subprocess.run(
                ["cc", "-O0", "-fno-builtin-memcmp", "-fno-pie", "-no-pie", str(source), "-o", str(binary)],
                text=True, capture_output=True,
            )
            if built.returncode:
                self.skipTest("fixture compiler does not support non-PIE ELF flags")
            if "ELF" not in subprocess.run(["file", str(binary)], text=True, capture_output=True).stdout:
                self.skipTest("independent verifier currently targets ELF objdump")

            rev = REVQ.extract_angr(str(binary))
            check = next(f for f in rev["functions"] if f["name"] == "check")
            angr_sites = {x["instruction_address"] for x in check["call_sites"] if x["api"] == "memcmp"}
            disassembly = subprocess.run(["objdump", "-d", str(binary)], text=True,
                                         capture_output=True, check=True).stdout
            body = re.search(r"<check>:\n(.*?)(?=\n[0-9a-f]+ <|\Z)", disassembly, re.S)
            self.assertIsNotNone(body)
            objdump_sites = {
                int(match.group(1), 16)
                for match in re.finditer(r"^\s*([0-9a-f]+):.*\bcall\w*\s+.*<memcmp@plt>", body.group(1), re.M)
            }
            self.assertEqual(len(objdump_sites), 2)
            self.assertEqual(angr_sites, objdump_sites)

            card = REVQ.compute_function_card(rev, "check")
            self.assertEqual([site["length"] for site in card["facts"]["compare_sites"]], [4, 4])
            self.assertTrue(all(site["length_status"] == "constant"
                                for site in card["facts"]["compare_sites"]))

            branch_card = REVQ.compute_function_card(rev, "branch_lengths")
            self.assertEqual({site["length"] for site in branch_card["facts"]["compare_sites"]}, {3, 7})
            self.assertTrue(all(site["length_status"] == "constant"
                                for site in branch_card["facts"]["compare_sites"]))

            input_card = REVQ.compute_function_card(rev, "input_length")
            self.assertEqual(input_card["facts"]["compare_sites"][0]["length_status"], "value_unresolved")
            self.assertIsNone(input_card["facts"]["compare_sites"][0]["length"])

            no_length_card = REVQ.compute_function_card(rev, "no_length_argument")
            self.assertEqual(no_length_card["facts"]["compare_sites"][0]["length_status"], "not_applicable")
            self.assertFalse(any(item["kind"] == "compare_length" for item in no_length_card["unresolved"]))


if __name__ == "__main__":
    unittest.main()
