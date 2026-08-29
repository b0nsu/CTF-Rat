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
                 contextlib.redirect_stderr(io.StringIO()):
                first = revq.load_or_extract(binary, "binutils", False)
                second = revq.load_or_extract(binary, "binutils", False)

            self.assertEqual(first["cache_state"], "miss")
            self.assertEqual(second["cache_state"], "hit")
            docs = list(iter_tool_results(root))
            self.assertEqual(len(docs), 2)
            self.assertEqual([doc["tool"]["name"] for doc in docs], ["revq", "revq"])
            self.assertEqual(sorted(doc["cache_state"] for doc in docs), ["hit", "miss"])
            self.assertEqual([doc["summary"]["engine"] for doc in docs], ["binutils", "binutils"])
            self.assertEqual(len({doc["invocation_id"] for doc in docs}), 2)

            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_requests"], 2)
            self.assertEqual(metrics["cache_hits"], 1)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["duplicate_tool_calls"], 0)


if __name__ == "__main__":
    unittest.main()
