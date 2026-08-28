import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
sys.path.insert(0, BIN)

from ratlib import analysis


class AnalysisProvenanceTests(unittest.TestCase):
    def _envelope_for(self, path):
        args = SimpleNamespace(binary=path, store=None, format="json", command=None)
        return analysis.envelope("rat-profile", path, args, {"test": True})

    def test_tool_build_digest_is_producer_identity_not_binary_identity(self):
        with tempfile.TemporaryDirectory() as d:
            first = os.path.join(d, "a.bin")
            second = os.path.join(d, "b.bin")
            with open(first, "wb") as fh:
                fh.write(b"first subject")
            with open(second, "wb") as fh:
                fh.write(b"second subject")

            a = self._envelope_for(first)
            b = self._envelope_for(second)

            self.assertNotEqual(a["inputs"][0]["digest"], b["inputs"][0]["digest"])
            self.assertEqual(a["tool"]["build_digest"], b["tool"]["build_digest"])
            self.assertEqual(a["tool"]["build_digest"], analysis.VERIFY_BUILD_DIGEST)
            self.assertNotEqual(a["tool"]["build_digest"], a["inputs"][0]["digest"])


if __name__ == "__main__":
    unittest.main()
