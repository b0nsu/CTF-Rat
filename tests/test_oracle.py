#!/usr/bin/env python3
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.oracle import classify, detect, shell_command, symsolve_argv


class OracleTests(unittest.TestCase):
    def fixture(self):
        return {
            "schema": "revq.v2",
            "engine": "angr",
            "bin": "/tmp/chall",
            "sha256": "a" * 64,
            "analysis_complete": True,
            "strings": [
                {"addr": 0x2000, "val": "Correct!", "xrefs": [{"func": "check", "addr": 0x401234}]},
                {"addr": 0x2010, "val": "Wrong password", "xrefs": [{"func": "check", "addr": 0x401280}]},
                {"addr": 0x2020, "val": "neutral text", "xrefs": [{"func": "main", "addr": 0x401000}]},
            ],
        }

    def test_classification_is_conservative(self):
        self.assertEqual(classify("Correct!"), "success")
        self.assertEqual(classify("Wrong password"), "failure")
        self.assertIsNone(classify("valid but wrong"))
        self.assertIsNone(classify("hello"))

    def test_xrefs_become_find_avoid_targets(self):
        doc = detect(self.fixture(), binary="/tmp/chall", cache={"hit": True})
        self.assertTrue(doc["ready"])
        self.assertEqual(doc["targets"]["find"], [0x401234])
        self.assertEqual(doc["targets"]["avoid"], [0x401280])
        self.assertEqual(doc["targets"]["find_str"], [])
        self.assertTrue(doc["cache"]["hit"])

    def test_string_fallback_when_xrefs_are_missing(self):
        rev = self.fixture()
        rev["strings"][0]["xrefs"] = []
        rev["strings"][1]["xrefs"] = []
        doc = detect(rev, binary="/tmp/chall")
        self.assertEqual(doc["targets"]["find_str"], ["Correct!"])
        self.assertEqual(doc["targets"]["avoid_str"], ["Wrong password"])

    def test_symsolve_wiring_preserves_constraints(self):
        doc = detect(self.fixture(), binary="/tmp/chall")
        argv = symsolve_argv(doc, stdin=16, printable=True, timeout=45)
        self.assertEqual(argv[0], "/tmp/chall")
        self.assertIn("--find", argv)
        self.assertIn("0x401234", argv)
        self.assertIn("--avoid", argv)
        self.assertIn("0x401280", argv)
        self.assertIn("--stdin", argv)
        self.assertIn("--printable", argv)
        cmd = shell_command(doc, stdin=16, printable=True)
        self.assertTrue(cmd.startswith("rat-adapt --root . --emit stdout symsolve "))


if __name__ == "__main__":
    unittest.main()
