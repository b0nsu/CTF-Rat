#!/usr/bin/env python3
import os
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.contracts import execute
from ratlib.telemetry import begin


class CacheProvenanceTests(unittest.TestCase):
    def test_cached_result_does_not_inherit_old_benchmark_run_id(self):
        with tempfile.TemporaryDirectory() as d:
            rat_root = os.path.join(d, ".rat")
            tool = os.path.join(d, "tool")
            with open(tool, "w", encoding="utf-8") as f:
                f.write("#!/usr/bin/env python3\nprint('ok')\n")
            os.chmod(tool, os.stat(tool).st_mode | stat.S_IXUSR)

            begin(d, run_id="bench-A0-1", ablation_id="A0", challenge_id="cache", attempt=1)
            first = execute([tool], root=rat_root, parameters={"case": "run-rebind"})
            self.assertEqual(first["run_id"], "bench-A0-1")
            self.assertFalse(first["provenance"]["cache"]["hit"])

            os.unlink(os.path.join(rat_root, "telemetry", "active.json"))
            second = execute([tool], root=rat_root, parameters={"case": "run-rebind"})
            self.assertEqual(second["run_id"], "local")
            self.assertTrue(second["provenance"]["cache"]["hit"])
            self.assertEqual(second["provenance"]["cache"]["source_invocation"], first["invocation_id"])
            self.assertNotEqual(second["invocation_id"], first["invocation_id"])


if __name__ == "__main__":
    unittest.main()
