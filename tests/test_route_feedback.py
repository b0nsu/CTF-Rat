import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
sys.path.insert(0, BIN)

from ratlib.artifact import _paths
from ratlib.route import route
from ratlib.route_feedback import load_feedback, record_query_result
from ratlib.state_v2 import Stream
from tests.direct_evidence_helper import direct_evidence_envelope


def _rat():
    loader = importlib.machinery.SourceFileLoader("rat_feedback_test", os.path.join(BIN, "rat"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _checker():
    rev = {"functions": [{"name": "check", "calls": ["memcmp"],
                           "strings": ["Correct", "Wrong"]}], "imports": []}
    interesting = [{"func": "check"}]
    return rev, interesting


def _card(binary_digest, *, complete=True, oracle=True):
    return {"schema": "rat.query-result/v1", "query": "func:check",
            "status": "ok" if complete else "partial",
            "facts": {"compare_sites": [{"api": "memcmp"}],
                      "oracle_candidates": ([{"kind": "success"}, {"kind": "failure"}]
                                            if oracle else [{"kind": "success"}])},
            "heuristics": {}, "artifacts": [],
            "coverage": {"complete": complete, "scope": "func:check", "omitted": None},
            "diagnostics": [], "provenance": {"binary_sha256": binary_digest, "cache": {"hit": False}}}


def _pwn_card(binary_digest):
    return {"schema": "rat.query-result/v1", "query": "pwn", "status": "ok",
            "facts": {"sinks": {"overflow_bounded": ["read"]}}, "heuristics": {},
            "artifacts": [], "coverage": {"complete": True, "scope": "binary-profile imports+protections",
                                          "omitted": None}, "diagnostics": [],
            "provenance": {"binary_sha256": binary_digest, "cache": {"hit": False}}}


class RouteFeedbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self.tmp.name, "checker")
        with open(self.binary, "wb") as source:
            source.write(b"checker fixture")
        import hashlib
        self.digest = "sha256:" + hashlib.sha256(b"checker fixture").hexdigest()
        self.rev, self.interesting = _checker()

    def tearDown(self):
        self.tmp.cleanup()

    def _route(self):
        initial = route(revq=self.rev, interesting=self.interesting, binary_digest=self.digest)
        feedback = load_feedback(self.tmp.name, self.digest, initial["next"])
        return route(revq=self.rev, interesting=self.interesting, binary_digest=self.digest,
                     probe_feedback=feedback)

    def test_route_query_route_resolves_exact_checker_probe(self):
        before = self._route()
        pid = before["decision"]["probe_id"]
        record_query_result(self.tmp.name, self.digest, _card(self.digest))
        after = self._route()
        self.assertFalse(any(action["probe_id"] == pid for action in after["next"]))
        self.assertEqual(after["feedback"][0]["status"], "resolved")
        self.assertNotIn("checker semantics and success/failure oracle remain unverified", after["unresolved"])
        self.assertEqual(after, self._route())

    def test_partial_mismatch_and_stale_result_cannot_resolve(self):
        before = self._route()
        record_query_result(self.tmp.name, self.digest, _card(self.digest, complete=False))
        partial = self._route()
        self.assertIsNone(partial["decision"])
        self.assertEqual(partial["next"][0]["probe_id"], before["decision"]["probe_id"])
        self.assertEqual(partial["feedback"][0]["status"], "partial")
        with open(self.binary, "ab") as source:
            source.write(b"changed")
        import hashlib
        changed = "sha256:" + hashlib.sha256(b"checker fixturechanged").hexdigest()
        changed_route = route(revq=self.rev, interesting=self.interesting, binary_digest=changed)
        self.assertEqual(load_feedback(self.tmp.name, changed, changed_route["next"]), {})
        artifact = record_query_result(self.tmp.name, self.digest, _card(self.digest))
        obj, _ = _paths(Stream(self.tmp.name).root, artifact)
        with open(obj, "wb") as source:
            source.write(b"corrupted")
        stale = self._route()
        self.assertIn(stale["feedback"][0]["status"], {"partial", "stale"})
        self.assertIsNone(stale["decision"])
        self.assertEqual(stale["next"][0]["probe_id"], before["decision"]["probe_id"])

    def test_invalidated_complete_result_restores_probe(self):
        record_query_result(self.tmp.name, self.digest, _card(self.digest))
        self.assertIsNone(self._route()["decision"])
        stream = Stream(self.tmp.name)
        observation_id = next(e["payload"]["observation_id"] for e in stream.read()
                              if e["type"] == "note.recorded"
                              and e["payload"].get("kind") == "route-query-result")
        stream.append("evidence.invalidated", {"observation_ids": [observation_id],
                                               "reason": "source retracted"})
        after = self._route()
        self.assertIsNone(after["decision"])
        self.assertEqual(after["next"][0]["query"], "rat query func")
        self.assertEqual(after["feedback"][0]["status"], "stale")

    def test_query_result_order_does_not_change_route(self):
        initial = route(revq=self.rev, interesting=self.interesting, binary_digest=self.digest)
        partial, complete = _card(self.digest, complete=False), _card(self.digest)
        record_query_result(self.tmp.name, self.digest, partial)
        record_query_result(self.tmp.name, self.digest, complete)
        left = route(revq=self.rev, interesting=self.interesting, binary_digest=self.digest,
                     probe_feedback=load_feedback(self.tmp.name, self.digest, initial["next"]))
        with tempfile.TemporaryDirectory() as other:
            record_query_result(other, self.digest, complete)
            record_query_result(other, self.digest, partial)
            right = route(revq=self.rev, interesting=self.interesting, binary_digest=self.digest,
                          probe_feedback=load_feedback(other, self.digest, initial["next"]))
        self.assertEqual(left, right)

    def test_safe_input_refutation_preserves_independent_heap_lead(self):
        profile = {"imports": ["read", "malloc", "free"]}
        initial = route(profile=profile, binary_digest=self.digest)
        stack = next(a for a in initial["next"] if a["target"].startswith("inspect-bounded-input"))
        stream = Stream(self.tmp.name)
        evidence = direct_evidence_envelope(root=stream.root, producer="gdbq",
                                            measurement=b"read length 8 into buffer[16]",
                                            subject_digest=self.digest)
        stream.append("observation.recorded", {
            "observation_id": "safe-read", "kind": "route.probe.refutation",
            "subject": {"binary_digest": self.digest}, "quality": {"level": "direct"},
            "validity": {"state": "active"}, "evidence": [evidence],
            "value": {"binary_digest": self.digest, "probe_id": stack["probe_id"],
                      "premise": stack["resolves"][0], "coverage_complete": True,
                      "callsites": [{"sink": "read", "destination_size": 16, "max_input_length": 8}],
                      "reason": "bounded read fits the destination"},
        })
        feedback = load_feedback(self.tmp.name, self.digest, initial["next"])
        after = route(profile=profile, binary_digest=self.digest, probe_feedback=feedback)
        self.assertNotIn("stack-overwrite", after["leads"])
        self.assertIn("heap-lifetime", after["leads"])
        self.assertNotIn(stack["probe_id"], {a["probe_id"] for a in after["next"]})
        stream.append("evidence.invalidated", {"observation_ids": ["safe-read"], "reason": "retracted"})
        feedback = load_feedback(self.tmp.name, self.digest, initial["next"])
        self.assertNotIn(stack["probe_id"], feedback)

    def test_competing_fact_backed_leads_remain_without_unique_decision(self):
        doc = route(profile={"imports": ["malloc", "free", "printf", "read"]},
                    binary_digest=self.digest)
        from ratlib.schema import validate
        validate(doc, "rat.route-result/v2")
        self.assertIsNone(doc["decision"])
        self.assertEqual(doc["commitment"], "provisional")

    def test_complete_pwn_capability_card_does_not_repeat_as_recommendation(self):
        profile = {"imports": ["read"]}
        before = route(profile=profile, binary_digest=self.digest)
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        feedback = load_feedback(self.tmp.name, self.digest, before["next"])
        after = route(profile=profile, binary_digest=self.digest, probe_feedback=feedback)
        self.assertIsNone(after["decision"])
        self.assertEqual(after["next"][0]["probe_id"], before["next"][0]["probe_id"])
        self.assertIn("does not establish", after["next"][0]["feedback_reason"])

    def test_frontdoor_route_query_route_updates_decision_and_governor(self):
        rat = _rat()
        facts = {"compare_sites": [{"api": "memcmp"}],
                 "oracle_candidates": [{"kind": "success"}, {"kind": "failure"}],
                 "callers": [], "callees": [], "strings": [], "call_sites": []}
        card = {"function": {"name": "check", "addr": 0x401000},
                "facts": facts, "unresolved": [], "heuristics": {}, "next": [],
                "provenance": {"binary_sha256": self.digest}}
        mod = SimpleNamespace(compute_interesting=lambda rev: self.interesting,
                              compute_function_card=lambda rev, name: card)
        args = SimpleNamespace(binary=self.binary, store=None, fast=True, format="json")
        qargs = SimpleNamespace(**vars(args), name="check", budget_bytes=16384)
        caps = {"angr": False}
        with patch.object(rat, "_doctor_capabilities", return_value=caps), \
             patch.object(rat, "_gather_profile", return_value={"imports": [], "facts": []}), \
             patch.object(rat, "_gather_revq", return_value=(mod, self.rev)), \
             patch.object(rat, "_record_revq_invocation"), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(rat.cmd_route(args), 0)
            first = json.loads(output.getvalue().splitlines()[-1])
            output.seek(0); output.truncate(0)
            self.assertEqual(rat.cmd_query_func(qargs), 0)
            output.seek(0); output.truncate(0)
            self.assertEqual(rat.cmd_route(args), 0)
            last = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(first["decision"]["action"], "rat query func")
        self.assertIsNone(last["decision"])
        self.assertEqual(last["feedback"][0]["status"], "resolved")
        self.assertNotIn("governor", last)

    def test_repeated_identical_query_results_do_not_reset_governor(self):
        rat = _rat()
        artifacts = []
        final = None
        for _ in range(8):
            final = rat._governor_wrap(self.tmp.name, "query:func", {"query": "func:check"},
                                       _card(self.digest))
            artifacts.append(record_query_result(self.tmp.name, self.digest, final))
        self.assertEqual(len(set(artifacts)), 1)
        self.assertTrue(final["governor"]["stuck"])


if __name__ == "__main__":
    unittest.main()
