import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
sys.path.insert(0, BIN)

from ratlib.metrics import aggregate, iter_tool_results


def _load_pwngadget():
    path = os.path.join(BIN, "pwngadget")
    loader = importlib.machinery.SourceFileLoader("pwngadget_telemetry_test", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class PwnGadgetInvocationTelemetryTests(unittest.TestCase):
    def test_miss_and_hit_are_persisted_as_tool_result_invocations(self):
        pwngadget = _load_pwngadget()
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as f:
                f.write(b"fixture-binary")
            root = os.path.join(d, ".rat")
            engine_output = "0x0000000000401234 : pop rdi ; ret\n"

            with patch.object(pwngadget, "_select_engine", return_value="ROPgadget"), \
                 patch.object(pwngadget, "_engine_version", return_value="7.4"), \
                 patch.object(pwngadget, "_run_gadget_engine", return_value=(engine_output, "ROPgadget", None)), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pwngadget.query_binary(binary, "pop rdi ; ret", "x86-64", 20, "json"), 0)
                self.assertEqual(pwngadget.query_binary(binary, "pop rdi ; ret", "x86-64", 20, "json"), 0)

            docs = list(iter_tool_results(root))
            self.assertEqual(len(docs), 2)
            self.assertEqual([d["tool"]["name"] for d in docs], ["pwngadget", "pwngadget"])
            self.assertEqual(sorted(d["cache_state"] for d in docs), ["hit", "miss"])

            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_requests"], 2)
            self.assertEqual(metrics["cache_hits"], 1)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["duplicate_tool_calls"], 0)


if __name__ == "__main__":
    unittest.main()
