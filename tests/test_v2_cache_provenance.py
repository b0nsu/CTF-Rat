import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.contracts import execute


class V2CacheProvenanceTests(unittest.TestCase):
    def test_cache_hit_is_a_fresh_invocation(self):
        with tempfile.TemporaryDirectory() as root:
            command = [sys.executable, "-c", "print('cache-me')"]
            first = execute(command, root=root, parameters={"case": "v2-hit"}, timeout=5)
            second = execute(command, root=root, parameters={"case": "v2-hit"}, timeout=5)

            self.assertFalse(first["provenance"]["cache"]["hit"])
            self.assertTrue(second["provenance"]["cache"]["hit"])
            self.assertEqual(
                second["provenance"]["cache"]["source_invocation"],
                first["invocation_id"],
            )
            self.assertNotEqual(second["invocation_id"], first["invocation_id"])
            self.assertEqual(second["artifacts"], first["artifacts"])
            self.assertEqual(second["summary"], first["summary"])


if __name__ == "__main__":
    unittest.main()
