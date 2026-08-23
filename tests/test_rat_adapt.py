#!/usr/bin/env python3
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
ADAPT = os.path.join(ROOT, "bin", "rat-adapt")


class RatAdaptTests(unittest.TestCase):
    def run_adapt(self, root, *args):
        return subprocess.run(
            [ADAPT, "--root", root, "--emit", "stdout", "--cache-meta", *args],
            text=True, capture_output=True, timeout=30,
        )

    def test_stdout_mode_replays_structured_cache(self):
        with tempfile.TemporaryDirectory() as d:
            first = self.run_adapt(d, "revq", "selftest")
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("ALL GREEN", first.stdout)
            self.assertIn("cache=miss", first.stderr)

            second = self.run_adapt(d, "revq", "selftest")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(second.stdout, first.stdout)
            self.assertIn("cache=hit", second.stderr)
            self.assertTrue(os.path.isfile(os.path.join(d, ".rat", "indexes", "cache.sqlite3")))

    def test_decomp_is_available_without_running_ghidra_for_help(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.run_adapt(d, "decomp", "--help")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage: decomp", result.stdout)


if __name__ == "__main__":
    unittest.main()
