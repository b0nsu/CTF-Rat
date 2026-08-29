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


def _load_revq():
    path = os.path.join(BIN, "revq")
    loader = importlib.machinery.SourceFileLoader("revq_telemetry_test", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RevqInvocationTelemetryTests(unittest.TestCase):
    def test_miss_and_hit_are_persisted_as_tool_result_invocations(self):
        revq = _load_revq()
        fixture = {
            "schema": revq.SCHEMA,
            "engine": "binutils",
            "arch": "AMD64",
            "pie": False,
            "stripped": False,
            "imports": [],
            "strings": [],
            "functions": [],
        }
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as fh:
                fh.write(b"fixture-binary")
            root = os.path.join(d, ".rat")

            with patch.object(revq, "extract_binutils", return_value=fixture), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(revq.main([binary, "--fast", "--json"]), 0)
                self.assertEqual(revq.main([binary, "--fast", "--json"]), 0)
            docs = list(iter_tool_results(root))
            self.assertEqual(len(docs), 2)
            self.assertEqual([doc["tool"]["name"] for doc in docs], ["revq", "revq"])
            self.assertEqual(sorted(doc["cache_state"] for doc in docs), ["hit", "miss"])
            self.assertEqual([doc["summary"]["engine"] for doc in docs], ["binutils", "binutils"])
            self.assertTrue(all(doc["parameters"]["operation"] == "json" for doc in docs))
            self.assertEqual(len({doc["invocation_id"] for doc in docs}), 2)

            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_requests"], 2)
            self.assertEqual(metrics["cache_hits"], 1)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["duplicate_tool_calls"], 0)

    def test_failed_selector_is_not_recorded_as_a_successful_invocation(self):
        revq = _load_revq()
        fixture = {
            "schema": revq.SCHEMA, "engine": "binutils", "arch": "AMD64",
            "pie": False, "stripped": False, "imports": [], "strings": [],
            "functions": [],
        }
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as fh:
                fh.write(b"fixture-binary")
            with patch.object(revq, "extract_binutils", return_value=fixture), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(revq.main([binary, "--fast", "--func", "missing"]), 1)
            self.assertEqual(list(iter_tool_results(os.path.join(d, ".rat"))), [])


if __name__ == "__main__":
    unittest.main()
