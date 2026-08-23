#!/usr/bin/env python3
"""Unit tests for the bounded FAST-path router."""
import importlib.machinery
import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)


def load_rat_module():
    path = os.path.join(BIN, "rat")
    loader = importlib.machinery.SourceFileLoader("rat_fast_test_module", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RatFastPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rat = load_rat_module()

    def test_rev_checker_routes_to_rev_fast(self):
        route = self.rat._route(
            "ELF 64-bit LSB pie executable",
            ["memcmp", "strlen"],
            ["Correct!"],
            "auto",
        )
        self.assertEqual(route["route"], "rev-fast")
        self.assertGreater(route["confidence"], 0.5)

    def test_unsafe_input_routes_to_pwn_fast(self):
        route = self.rat._route(
            "ELF 64-bit LSB executable",
            ["gets", "read"],
            [],
            "auto",
        )
        self.assertEqual(route["route"], "pwn-fast")

    def test_ambiguous_binary_stays_mixed(self):
        route = self.rat._route("ELF 64-bit LSB executable", [], [], "auto")
        self.assertEqual(route["route"], "mixed-fast")
        self.assertEqual(route["confidence"], 0.5)

    def test_operator_override_is_deterministic(self):
        route = self.rat._route("unknown", [], [], "rev")
        self.assertEqual(route["route"], "rev-fast")
        self.assertEqual(route["confidence"], 1.0)

    def test_snapshot_respects_byte_budget(self):
        doc = {
            "facts": [{"state": "confirmed", "text": "A" * 300}],
            "primitives": [],
            "hypotheses": [],
            "ruled_out": [],
            "unknowns": [],
            "next": [],
        }
        rendered = self.rat._bounded_text(doc, 160)
        self.assertLessEqual(len(rendered.encode()), 160)

    def test_next_steps_do_not_enter_deep_by_default(self):
        steps = self.rat._next_steps("rev-fast", "/tmp/chall")
        self.assertTrue(any("revq" in step for step in steps))
        self.assertFalse(any("rat-phase enter" in step for step in steps))


if __name__ == "__main__":
    unittest.main()
