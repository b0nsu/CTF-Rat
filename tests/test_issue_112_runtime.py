import importlib.machinery
import importlib.util
import json
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
from ratlib.metrics import aggregate, iter_tool_results
from ratlib.state_v2 import Stream
from tests.test_telemetry import envelope


def load_revq():
    loader = importlib.machinery.SourceFileLoader("_issue112_revq", str(BIN / "revq"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


MINIMAL_WASM = (b"\0asm\x01\0\0\0"
                b"\x01\x05\x01\x60\x00\x01\x7f"
                b"\x03\x02\x01\x00"
                b"\x07\x0a\x01\x06answer\x00\x00"
                b"\x0a\x06\x01\x04\x00\x41\x2a\x0b")


class WasmPathTests(unittest.TestCase):
    def test_unsupported_wasm_version_has_explicit_scope_error(self):
        with tempfile.TemporaryDirectory() as d:
            module = Path(d) / "component.wasm"
            module.write_bytes(b"\0asm\x0d\0\0\0")
            result = subprocess.run([sys.executable, str(BIN / "rat-wasm"), "inspect", str(module)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 4)
            self.assertIn("core module v1 required", json.loads(result.stdout)["diagnostic"])

    def test_route_and_bounded_function_inventory_avoid_angr_loader_error(self):
        with tempfile.TemporaryDirectory() as d:
            module = Path(d) / "tiny.wasm"
            module.write_bytes(MINIMAL_WASM)
            env = dict(os.environ, CTF_HOME=str(ROOT), PYTHONPATH=str(BIN))
            route = subprocess.run([sys.executable, str(BIN / "rat"), "route", str(module), "--format", "json"],
                                   env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(route.returncode, 0, route.stderr)
            doc = json.loads(route.stdout)
            self.assertIn("wasm-platform", [signal["kind"] for signal in doc["signals"]])
            self.assertNotIn("analysis_failed", [diag["code"] for diag in doc["diagnostics"]])
            inspected = subprocess.run([sys.executable, str(BIN / "rat-wasm"), "inspect", str(module), "--func", "0"],
                                       env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertEqual(json.loads(inspected.stdout)["function"]["name"], "answer")

    @unittest.skipUnless(importlib.util.find_spec("wasmtime"), "optional independent Wasmtime engine")
    def test_wasmtime_execution_and_state_provenance(self):
        import wasmtime
        wat = '''(module
          (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 8) "Correct!\\n")
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 8))
            (i32.store (i32.const 4) (i32.const 9))
            (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 20)))))'''
        with tempfile.TemporaryDirectory() as d:
            module = Path(d) / "check.wasm"
            module.write_bytes(wasmtime.wat2wasm(wat))
            input_file = Path(d) / "input"
            input_file.write_bytes(b"candidate\n")
            args = [sys.executable, str(BIN / "rat-wasm"), "verify", str(module),
                    "--stdin-file", str(input_file), "--expect-stdout", "Correct!",
                    "--record-state-dir", d]
            passed = subprocess.run(args, capture_output=True, text=True, timeout=20)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            doc = json.loads(passed.stdout)
            self.assertEqual((doc["status"], doc["engine"], doc["runtime"]["stdout"]),
                             ("pass", "wasmtime", "Correct!\n"))
            self.assertTrue(doc["state_recorded"])
            observation = next(iter(Stream(d).view()["observations"].values()))
            self.assertEqual(observation["kind"], "rev.wasm.runtime-verification")
            self.assertEqual(observation["quality"]["level"], "heuristic")
            failed = subprocess.run(args[:args.index("--expect-stdout") + 1] + ["Other"],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(failed.returncode, 1)
            self.assertEqual(json.loads(failed.stdout)["status"], "fail")


class AngrDiagnosticsTests(unittest.TestCase):
    def test_engine_error_is_partial_and_logging_is_restored(self):
        revq = load_revq()
        logger = logging.getLogger("pyvex")
        level, propagate, handlers = logger.level, logger.propagate, list(logger.handlers)
        def fake_extract(_path, diagnostics):
            logger.error("Unsupported Dirty amd64g_dirtyhelper_CPUID_avx2")
            return {"diagnostics": list(diagnostics)}
        with mock.patch.object(revq, "_extract_angr_impl", side_effect=fake_extract):
            result = revq.extract_angr("unused")
        self.assertEqual(revq._engine_analysis_status(result["diagnostics"]), "partial")
        self.assertEqual((logger.level, logger.propagate, logger.handlers), (level, propagate, handlers))

    def test_late_engine_error_survives_bounded_warning_capture(self):
        revq = load_revq()
        logger = logging.getLogger("pyvex")
        def fake_extract(_path, diagnostics):
            for index in range(8):
                logger.warning("warning %d", index)
            logger.error("Unsupported Dirty amd64g_dirtyhelper_CPUID_avx2")
            return {"diagnostics": list(diagnostics)}
        with mock.patch.object(revq, "_extract_angr_impl", side_effect=fake_extract):
            result = revq.extract_angr("unused")
        self.assertEqual(len(result["diagnostics"]), 8)
        self.assertEqual(revq._engine_analysis_status(result["diagnostics"]), "partial")


class CaptureOutcomeTests(unittest.TestCase):
    def test_zero_exit_structured_result_without_explicit_class_is_unverified(self):
        with tempfile.TemporaryDirectory() as d:
            payload = Path(d) / "child-result.json"
            payload.write_text(json.dumps(envelope()))
            command = [sys.executable, str(BIN / "rat-capture"), "--store", str(Path(d) / ".rat"),
                       "--", sys.executable, "-c", "import sys;sys.stdout.write(open(sys.argv[1]).read())",
                       str(payload)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0)
            self.assertIn('"class":"analysis-unverified"', result.stderr)

    def test_telemetry_failure_preserves_child_exit(self):
        with tempfile.TemporaryDirectory() as d:
            store = Path(d) / "store-file"
            store.write_text("cannot be a directory")
            command = [sys.executable, str(BIN / "rat-capture"), "--store", str(store),
                       "--", sys.executable, "-c", "import sys;sys.exit(7)"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 7)
            self.assertIn('"child_exit_code":7', result.stderr)
            self.assertIn("telemetry unavailable", result.stderr)

    def test_help_and_fallback_are_separate_from_valid_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            base = [sys.executable, str(BIN / "rat-capture"), "--store", str(Path(d) / ".rat")]
            help_call = subprocess.run(base + ["--purpose", "help", "--", sys.executable, "-c", "print('usage')"],
                                       capture_output=True, text=True, timeout=20)
            fallback_call = subprocess.run(base + ["--", sys.executable, "-c",
                                                   "import sys;print('disassembly');print('RAT_STATUS=fallback',file=sys.stderr)"],
                                           capture_output=True, text=True, timeout=20)
            self.assertEqual((help_call.returncode, fallback_call.returncode), (0, 0))
            counts = aggregate(iter_tool_results(str(Path(d) / ".rat")))["result_class_counts"]
            self.assertEqual(counts, {"help": 1, "fallback": 1})

    def test_bounded_capture_preserves_child_failure_and_metrics_class(self):
        with tempfile.TemporaryDirectory() as d:
            command = [sys.executable, str(BIN / "rat-capture"), "--limit", "8", "--store", str(Path(d) / ".rat"),
                       "--", sys.executable, "-c", "import sys;print('X'*100);sys.exit(7)"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, "XXXXXXXX")
            self.assertIn('"child_exit_code":7', result.stderr)
            docs = list(iter_tool_results(str(Path(d) / ".rat")))
            self.assertEqual(len(docs), 1)
            self.assertEqual(docs[0]["status"], "error")
            self.assertEqual(aggregate(docs)["result_class_counts"], {"call-failed": 1})


if __name__ == "__main__":
    unittest.main()
