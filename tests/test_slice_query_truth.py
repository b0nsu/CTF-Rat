import importlib.machinery
import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)


def _load_rat():
    loader = importlib.machinery.SourceFileLoader("_rat_slice_truth", os.path.join(BIN, "rat"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


RAT = _load_rat()


class SliceTruthTests(unittest.TestCase):
    def test_completion_truth_table(self):
        cases = [
            ({"status": "ok", "summary": {"unresolved_aliases": 0, "unresolved_indirect_calls": 0}}, True),
            ({"status": "ok", "summary": {"unresolved_aliases": 1, "unresolved_indirect_calls": 0}}, False),
            ({"status": "ok", "summary": {"unresolved_aliases": 0, "unresolved_indirect_calls": 1}}, False),
            ({"status": "ok", "summary": {"unresolved_aliases": 0, "unresolved_indirect_calls": 2}}, False),
            ({"status": "ok", "summary": {}}, False),
            ({"status": "ok", "summary": {"unresolved_aliases": None, "unresolved_indirect_calls": 0}}, False),
            ({"status": "ok", "summary": {"unresolved_aliases": "0", "unresolved_indirect_calls": 0}}, False),
            ({"status": "ok", "summary": {"unresolved_aliases": False, "unresolved_indirect_calls": 0}}, False),
            ({"status": "ok", "summary": {"unresolved_aliases": -1, "unresolved_indirect_calls": 0}}, False),
            ({"status": "partial", "summary": {"unresolved_aliases": 0, "unresolved_indirect_calls": 0}}, False),
            ({"status": "partial", "summary": {}}, False),
        ]
        for doc, expected in cases:
            with self.subTest(doc=doc):
                self.assertIs(RAT._slice_complete(doc), expected)

    def _project(self, slice_doc):
        profile = {"artifacts": [{"digest": "sha256:" + "1" * 64}]}
        responses = [
            (0, json.dumps(profile), ""),
            (0, json.dumps(slice_doc), ""),
        ]
        args = type("Args", (), {
            "binary": "/tmp/chall",
            "backward": "0x401000",
            "depth": 2,
            "source": "stdin",
            "store": "/tmp/store",
            "format": "json",
        })()
        with mock.patch.object(RAT, "_check_binary", return_value=None), \
             mock.patch.object(RAT, "resolve_index_root", return_value="/tmp/store"), \
             mock.patch.object(RAT, "_run_subprocess", side_effect=responses), \
             mock.patch.object(RAT, "_governor_wrap", side_effect=lambda _root, _action, _key, doc: doc), \
             mock.patch.object(RAT, "_emit", side_effect=lambda doc, _code, _fmt: doc):
            return RAT.cmd_query_slice(args)

    def test_partial_producer_cannot_claim_complete_coverage(self):
        doc = self._project({
            "status": "partial",
            "summary": {"analysis_kind": "data", "coverage": "unavailable"},
            "diagnostics": [{"message": "angr dependency missing; no synthetic slice emitted", "severity": "warning"}],
            "inputs": [],
            "artifacts": [],
            "provenance": {"cache": {"hit": False}},
        })
        self.assertEqual(doc["status"], "partial")
        self.assertFalse(doc["coverage"]["complete"])

    def test_future_multi_indirect_count_is_incomplete(self):
        doc = self._project({
            "status": "ok",
            "summary": {
                "target": {"address": "0x401000", "function": "main"},
                "within_function": {},
                "interproc": {"depth": 2},
                "claim": "dependency-candidate",
                "unresolved_aliases": 0,
                "unresolved_indirect_calls": 2,
            },
            "diagnostics": [],
            "inputs": [{"digest": "sha256:" + "2" * 64}],
            "artifacts": [],
            "provenance": {"cache": {"hit": False}},
        })
        self.assertEqual(doc["status"], "partial")
        self.assertFalse(doc["coverage"]["complete"])

    def test_clean_producer_is_complete(self):
        doc = self._project({
            "status": "ok",
            "summary": {
                "target": {"address": "0x401000", "function": "main"},
                "within_function": {},
                "interproc": {"depth": 2},
                "claim": "dependency-candidate",
                "unresolved_aliases": 0,
                "unresolved_indirect_calls": 0,
            },
            "diagnostics": [],
            "inputs": [{"digest": "sha256:" + "2" * 64}],
            "artifacts": [],
            "provenance": {"cache": {"hit": False}},
        })
        self.assertEqual(doc["status"], "ok")
        self.assertTrue(doc["coverage"]["complete"])


if __name__ == "__main__":
    unittest.main()
