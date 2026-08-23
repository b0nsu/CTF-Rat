#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
BIN = os.path.join(ROOT, "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.function_card import SCHEMA, build_card, find_function


def fixture():
    return {
        "schema": 2,
        "engine": "angr",
        "analysis_complete": True,
        "pie": True,
        "bin": "/fixture/chall",
        "evasion": [],
        "functions": [
            {"name": "main", "addr": 0x401230, "size": 120, "nblocks": 5, "ninstr": 30,
             "count_quality": "cfg", "calls": ["read", "check", "puts"],
             "strings": ["Enter license:"], "ncallers": 1},
            {"name": "check", "addr": 0x401180, "size": 90, "nblocks": 4, "ninstr": 24,
             "count_quality": "cfg", "calls": ["memcmp", "strlen"],
             "strings": ["Correct!", "Wrong password"], "ncallers": 1},
            {"name": "noise_helper", "addr": 0x401300, "size": 32, "nblocks": 2, "ninstr": 10,
             "count_quality": "cfg", "calls": [], "strings": [], "ncallers": 2},
        ],
    }


class FunctionCardV2Tests(unittest.TestCase):
    def test_checker_card_uses_only_existing_revq_facts(self):
        card = build_card(fixture(), "check", binary="/tmp/chall", cache={"hit": True})
        self.assertEqual(card["schema"], SCHEMA)
        self.assertEqual(card["role"]["label"], "checker")
        self.assertEqual(card["callers"], ["main"])
        self.assertEqual(card["compare_calls"], ["memcmp"])
        self.assertEqual({x["kind"] for x in card["oracle"]["signals"]}, {"success", "failure"})
        self.assertEqual(card["oracle"]["distance_calls"], 0)
        self.assertEqual(card["compare_sites"], [])
        self.assertEqual(card["branch_sites"], [])
        self.assertEqual(card["data_dependencies"], [])
        self.assertIn("not available", card["coverage"]["data_dependencies"])

    def test_caller_gets_oracle_distance_without_inventing_oracle_string(self):
        card = build_card(fixture(), "main")
        self.assertEqual(card["role"]["label"], "input")
        self.assertEqual(card["oracle"]["signals"], [])
        self.assertEqual(card["oracle"]["distance_calls"], 1)
        self.assertTrue(card["oracle"]["reachable_oracle"])

    def test_partial_match_must_be_unique(self):
        rev = fixture()
        rev["functions"].append({"name": "check_extra", "addr": 0x401400, "calls": [], "strings": []})
        with self.assertRaises(ValueError):
            find_function(rev, "check_")

    def test_cli_can_render_fixture_without_angr(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            revmap = os.path.join(d, "rev.json")
            open(binary, "wb").write(b"fixture")
            with open(revmap, "w", encoding="utf-8") as f:
                json.dump(fixture(), f)
            cli = os.path.join(BIN, "rat-func-v2")
            p = subprocess.run([sys.executable, cli, binary, "check", "--revmap", revmap, "--format", "json"],
                               text=True, capture_output=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            card = json.loads(p.stdout)
            self.assertEqual(card["function"]["name"], "check")
            self.assertEqual(card["role"]["label"], "checker")


if __name__ == "__main__":
    unittest.main()
