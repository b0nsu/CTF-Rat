import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import types
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)


def load_tool(name):
    path = os.path.join(BIN, name)
    loader = importlib.machinery.SourceFileLoader("format_test_" + name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def capture(call):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = call()
    return code, output.getvalue()


class MachineFormatFlagTests(unittest.TestCase):
    def test_revq_json_flag_is_an_alias_for_format(self):
        revq = load_tool("revq")
        with tempfile.NamedTemporaryFile() as binary:
            with patch.object(revq, "load_or_extract", return_value={"schema": "fixture"}), \
                 patch.object(revq, "_canonical_index", return_value=(None, "fixture-key")), \
                 patch.object(revq, "_persist_invocation"):
                code_a, out_a = capture(lambda: revq.main([binary.name, "--format", "json"]))
                code_b, out_b = capture(lambda: revq.main([binary.name, "--json"]))
        self.assertEqual((code_a, code_b), (0, 0))
        self.assertEqual(json.loads(out_a), json.loads(out_b))

    def test_revq_funcs_view_takes_precedence_over_raw_json(self):
        revq = load_tool("revq")
        fixture = {"schema": "fixture", "bin": "fixture", "sha256": "a" * 64,
                   "engine": "binutils", "functions": [
                       {"name": "main", "addr": 0x401000, "size": 32, "nblocks": 2,
                        "ninstr": 8, "ncallers": 0, "calls": [], "strings": []}]}
        with tempfile.NamedTemporaryFile() as binary:
            with patch.object(revq, "load_or_extract", return_value=fixture), \
                 patch.object(revq, "_canonical_index", return_value=(None, "fixture-key")), \
                 patch.object(revq, "_persist_invocation"):
                code, output = capture(lambda: revq.main([binary.name, "--funcs", "--format", "json"]))
        document = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(document["schema"], "rat.revq-functions/v1")
        self.assertEqual([item["name"] for item in document["functions"]], ["main"])

    def test_pwncrash_format_json_keeps_json_alias(self):
        pwncrash = load_tool("pwncrash")
        context = types.SimpleNamespace(log_level=None, log_console=None)
        fake_pwn = types.SimpleNamespace(
            Corefile=object, cyclic=lambda length, n=4: b"A" * length,
            cyclic_find=lambda value, n=4: 0, context=context,
        )
        stream = types.SimpleNamespace(preview=b"", total_bytes=0)
        run_result = types.SimpleNamespace(
            exit_code=0, signal=None, timed_out=False, stdout=stream, stderr=stream,
        )
        with tempfile.NamedTemporaryFile() as binary, \
             patch.dict(sys.modules, {"pwn": fake_pwn}), \
             patch.object(pwncrash, "run", return_value=run_result):
            code_a, out_a = capture(lambda: pwncrash.main([binary.name, "--format", "json"]))
            code_b, out_b = capture(lambda: pwncrash.main([binary.name, "--json"]))
        self.assertEqual((code_a, code_b), (2, 2))
        self.assertEqual(json.loads(out_a), json.loads(out_b))

    def test_pwncalc_format_works_before_and_after_subcommand_and_keeps_json_alias(self):
        pwncalc = load_tool("pwncalc")
        base = ["base", "--leak", "0x12345000", "--offset", "0x12345000"]
        code_a, out_a = capture(lambda: pwncalc.main(["--format", "json", *base]))
        code_b, out_b = capture(lambda: pwncalc.main([*base, "--format", "json"]))
        code_c, out_c = capture(lambda: pwncalc.main([*base, "--json"]))
        self.assertEqual((code_a, code_b, code_c), (0, 0, 0))
        self.assertEqual(json.loads(out_a), json.loads(out_b))
        self.assertEqual(json.loads(out_a), json.loads(out_c))

    def test_pwnscope_json_flag_is_an_alias_for_format(self):
        pwnscope = load_tool("pwnscope")
        script = os.path.join(BIN, "pwnscope")
        code_a, out_a = capture(lambda: pwnscope.main([script, "--format", "json"]))
        code_b, out_b = capture(lambda: pwnscope.main([script, "--json"]))
        self.assertEqual(code_a, code_b)
        self.assertEqual(json.loads(out_a), json.loads(out_b))

    def test_pwnropcheck_json_flag_is_an_alias_for_format(self):
        pwnropcheck = load_tool("pwnropcheck")
        args = ["--chain", "0x401000"]
        code_a, out_a = capture(lambda: pwnropcheck.main([*args, "--format", "json"]))
        code_b, out_b = capture(lambda: pwnropcheck.main([*args, "--json"]))
        self.assertEqual((code_a, code_b), (2, 2))
        self.assertEqual(json.loads(out_a), json.loads(out_b))


if __name__ == "__main__":
    unittest.main()
