#!/usr/bin/env python3
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.telemetry import (begin, finish, record, record_cache,
                              record_cache_write, record_model, record_tool,
                              summarize)
from ratlib.contracts import execute


class TelemetryTests(unittest.TestCase):
    def test_opt_in_and_summary(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertFalse(record("tool", {"tool": "x"}, root=root))
            begin(root, run_id="A0-001", variant="A0", model="solver-medium")
            artifact = os.path.join(root, "chall")
            with open(artifact, "wb") as f:
                f.write(b"x")
            record_tool(["revq", "chall", "--interesting"], duration_ms=100, exit_code=0, cwd=root, root=root)
            record_tool(["revq", "./chall", "--interesting"], duration_ms=120, exit_code=0, cwd=root, root=root)
            record_tool(["decomp", "chall", "main"], duration_ms=300, exit_code=0, cwd=root, root=root)
            record_cache(tool="rat-adapt", key="k1", hit=False, root=root)
            record_cache_write(tool="rat-adapt", key="k1", root=root)
            record_cache(tool="rat-adapt", key="k1", hit=True, root=root)
            record_model(input_tokens=1000, output_tokens=200, cache_read_tokens=600,
                         cache_creation_tokens=50, context_tokens=7000, duration_ms=900,
                         root=root)
            record_model(input_tokens=500, output_tokens=100, context_tokens=9000,
                         duration_ms=400, root=root)
            record("deep", {"reason": "ambiguous"}, root=root)
            record("verify", {"verified": True, "flag_found": True}, root=root)
            finish(root, status="solved", verified=True, flag_found=True)
            doc = summarize(root, "A0-001")
            self.assertEqual(doc["tools"]["calls"], 3)
            self.assertEqual(doc["tools"]["duplicate_calls"], 1)
            self.assertEqual(doc["tools"]["counts"]["revq"], 2)
            self.assertEqual(doc["cache"]["reads"], 2)
            self.assertEqual(doc["cache"]["hits"], 1)
            self.assertEqual(doc["cache"]["writes"], 1)
            self.assertEqual(doc["cache"]["hit_ratio"], 0.5)
            self.assertEqual(doc["peak_context_tokens"], 9000)
            self.assertEqual(doc["tokens"]["input"], 1500)
            self.assertEqual(doc["tokens"]["cache_read"], 600)
            self.assertEqual(doc["deep_escalations"], 1)
            self.assertTrue(doc["verified_solve"])
            self.assertTrue(doc["flag_found"])
            self.assertIsNotNone(doc["time_to_flag_ms"])

    def test_structured_cache_reports_real_hit_provenance(self):
        with tempfile.TemporaryDirectory() as root:
            begin(root, run_id="cache-001", variant="cache")
            tool = os.path.join(root, "fixture-tool")
            with open(tool, "w", encoding="utf-8") as f:
                f.write("#!/usr/bin/env python3\nprint(\"fixture-output\")\n")
            os.chmod(tool, 0o755)
            rat_root = os.path.join(root, ".rat")
            first = execute([tool], root=rat_root)
            second = execute([tool], root=rat_root)
            self.assertFalse(first["provenance"]["cache"]["hit"])
            self.assertTrue(second["provenance"]["cache"]["hit"])
            self.assertEqual(second["provenance"]["cache"]["source_invocation"], first["invocation_id"])
            self.assertNotEqual(second["invocation_id"], first["invocation_id"])
            finish(root, status="solved")
            doc = summarize(root, "cache-001")
            self.assertEqual((doc["cache"]["reads"], doc["cache"]["hits"], doc["cache"]["writes"]), (2, 1, 1))

    def test_active_run_is_fail_closed_without_force(self):
        with tempfile.TemporaryDirectory() as root:
            begin(root, run_id="first")
            with self.assertRaises(ValueError):
                begin(root, run_id="second")
            begin(root, run_id="second", force=True)
            finish(root, status="abandoned")
            self.assertEqual(summarize(root, "second")["run_id"], "second")


if __name__ == "__main__":
    unittest.main()
