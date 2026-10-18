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
from ratlib.route_feedback import load_feedback, record_followup_result, record_query_result
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

    def test_cross_binary_result_cannot_be_relabelled_or_persisted(self):
        original = _card(self.digest)
        imported = json.loads(json.dumps(original))
        foreign_digest = "sha256:" + "a" * 64
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            record_query_result(self.tmp.name, foreign_digest, original)
        self.assertEqual(original, imported)
        self.assertEqual(Stream(self.tmp.name).read(), [])

    def test_revq_bare_hex_digest_is_normalized_without_changing_source(self):
        card = _card(self.digest)
        card["provenance"]["binary_sha256"] = self.digest.split(":", 1)[1]
        digest = record_query_result(self.tmp.name, self.digest, card)
        from ratlib.artifact import get
        stored = json.loads(get(digest, root=Stream(self.tmp.name).root))
        self.assertEqual(stored["provenance"]["binary_sha256"], self.digest)
        self.assertEqual(card["provenance"]["binary_sha256"], self.digest.split(":", 1)[1])
        after = self._route()
        self.assertEqual(after["feedback"][0]["status"], "resolved")

    def test_frontdoor_changed_binary_marks_query_partial_without_feedback(self):
        rat = _rat()
        stale = _card("sha256:" + "b" * 64)
        rat._record_query_feedback(self.binary, stale)
        self.assertEqual(stale["status"], "partial")
        self.assertFalse(stale["coverage"]["complete"])
        self.assertTrue(any(d["code"] == "stale_cache" for d in stale["diagnostics"]))
        from ratlib.schema import validate
        validate(stale, "rat.query-result/v1")
        self.assertFalse(any(e["type"] == "note.recorded" and
                             e["payload"].get("kind") == "route-query-result"
                             for e in Stream(self.tmp.name).read()))

    def test_feedback_uses_one_snapshot_and_scopes_query_notes(self):
        record_query_result(self.tmp.name, self.digest, _card(self.digest))
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        initial = route(revq=self.rev, interesting=self.interesting,
                        binary_digest=self.digest)
        original_read = Stream.read
        reads = []

        def counted_read(instance):
            reads.append(instance.path)
            return original_read(instance)

        with patch.object(Stream, "read", counted_read):
            feedback = load_feedback(self.tmp.name, self.digest, initial["next"])
        self.assertEqual(len(reads), 1, "routing feedback should read STATE only once")
        self.assertEqual(feedback[initial["decision"]["probe_id"]]["status"], "resolved")

    def test_route_query_route_resolves_exact_checker_probe(self):
        before = self._route()
        pid = before["decision"]["probe_id"]
        record_query_result(self.tmp.name, self.digest, _card(self.digest))
        after = self._route()
        self.assertFalse(any(action["probe_id"] == pid for action in after["next"]))
        self.assertEqual(after["feedback"][0]["status"], "resolved")
        self.assertEqual(after["commitment"], "unknown")
        self.assertNotIn("checker semantics and success/failure oracle remain unverified", after["unresolved"])
        self.assertTrue(any("executable branch semantics remain unverified" in item
                            for item in after["unresolved"]))
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

    def test_free_form_refutation_cannot_erase_unrelated_lead(self):
        profile = {"imports": ["malloc", "free"]}
        initial = route(profile=profile, binary_digest=self.digest)
        heap = next(action for action in initial["next"] if action["query"] == "rat query pwn")
        stream = Stream(self.tmp.name)
        unrelated = direct_evidence_envelope(root=stream.root, producer="gdbq",
                                             measurement=b"unrelated debugger observation",
                                             subject_digest=self.digest)
        stream.append("observation.recorded", {
            "observation_id": "unsupported-refutation",
            "kind": "route.probe.refutation",
            "subject": {"binary_digest": self.digest},
            "quality": {"level": "direct"}, "validity": {"state": "active"},
            "evidence": [unrelated],
            "value": {"binary_digest": self.digest, "probe_id": heap["probe_id"],
                      "premise": heap["resolves"][0], "coverage_complete": True,
                      "conclusion": "premise-refuted"},
        })
        feedback = load_feedback(self.tmp.name, self.digest, initial["next"])
        self.assertNotIn(heap["probe_id"], feedback)
        after = route(profile=profile, binary_digest=self.digest, probe_feedback=feedback)
        self.assertIn("heap-lifetime", after["leads"])
        self.assertIn(heap["probe_id"], {a["probe_id"] for a in after["next"]})

    def test_one_safe_input_callsite_cannot_refute_unenumerated_sinks(self):
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
        self.assertNotIn(stack["probe_id"], feedback)
        after = route(profile=profile, binary_digest=self.digest, probe_feedback=feedback)
        self.assertIn("stack-overwrite", after["leads"])
        self.assertIn("heap-lifetime", after["leads"])
        self.assertIn(stack["probe_id"], {a["probe_id"] for a in after["next"]})
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
        self.assertEqual(after["feedback"][0]["status"], "partial")
        self.assertEqual(after["next"][0]["query"], "pwncrash")
        self.assertEqual(after["next"][0]["source_probe_id"], before["next"][0]["probe_id"])
        self.assertEqual(after["decision"]["action"], "pwncrash")
        self.assertEqual(after["commitment"], "provisional")
        self.assertIn("stack-overwrite", after["leads"])

    def test_followup_probe_result_advances_route_without_repeating_action(self):
        rat = _rat()
        for profile, rev, query, selector in (
                ({"imports": ["printf", "read"]},
                 {"functions": [{"name": "main", "calls": ["printf"]}]},
                 "decomp", "main"),
                ({"imports": ["read"]}, None, "pwncrash", "")):
            with self.subTest(query=query):
                record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
                before = rat._route_with_feedback(self.binary, profile, rev, None)
                self.assertIn(query, {action["query"] for action in before["next"]})
                record_followup_result(self.tmp.name, self.digest, query, {
                    "query": query, "selector": selector, "binary_digest": self.digest,
                    "status": "ok", "result": "bounded fixture",
                })
                after = rat._route_with_feedback(self.binary, profile, rev, None)
                self.assertNotIn(query, {action["query"] for action in after["next"]})
                self.assertTrue(any(item["status"] == "inspected" for item in after["feedback"]))
                self.assertTrue(after["unresolved"], "tool completion must not prove a vulnerability")
                self.assertNotEqual(after["commitment"], "committed")

    def test_partial_followup_remains_visible_without_recommendation(self):
        rat = _rat()
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        before = rat._route_with_feedback(self.binary, {"imports": ["read"]}, None, None)
        self.assertEqual(before["decision"]["action"], "pwncrash")
        record_followup_result(self.tmp.name, self.digest, "pwncrash", {
            "query": "pwncrash", "selector": "", "binary_digest": self.digest,
            "status": "partial", "report": {"verdict": "inconclusive"},
        })
        after = rat._route_with_feedback(self.binary, {"imports": ["read"]}, None, None)
        self.assertIsNone(after["decision"])
        self.assertEqual(after["next"][0]["query"], "pwncrash")
        self.assertTrue(any(item["status"] == "partial" and
                            item["probe_id"] == after["next"][0]["probe_id"]
                            for item in after["feedback"]))

    def test_stable_crash_without_pc_control_is_not_resolved(self):
        rat = _rat()
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        report = {"schema": "rat.pwncrash/v1", "verdict": "crash-reproduced",
                  "binary": {"sha256": self.digest}, "input": {"kind": "cyclic", "length": 256},
                  "core": {"control_cyclic_offset": None}}
        record_followup_result(self.tmp.name, self.digest, "pwncrash", {
            "query": "pwncrash", "selector": "", "binary_digest": self.digest,
            "status": "ok", "report": report,
        })
        after = rat._route_with_feedback(self.binary, {"imports": ["read"]}, None, None)
        self.assertTrue(any(item["status"] == "inspected" for item in after["feedback"]))
        self.assertIn("prove a concrete overwrite or PC-control primitive; import presence is insufficient",
                      after["unresolved"])

    def test_malformed_followup_report_cannot_crash_route_or_resolve(self):
        rat = _rat()
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        record_followup_result(self.tmp.name, self.digest, "pwncrash", {
            "query": "pwncrash", "selector": "", "binary_digest": self.digest,
            "status": "ok", "report": ["not a report"],
        })
        after = rat._route_with_feedback(self.binary, {"imports": ["read"]}, None, None)
        self.assertTrue(any(item["status"] == "inspected" for item in after["feedback"]))

    def test_measured_pc_control_updates_premise_but_not_primitive(self):
        rat = _rat()
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        report = {"schema": "rat.pwncrash/v1", "verdict": "crash-reproduced",
                  "binary": {"sha256": self.digest}, "input": {"kind": "cyclic", "length": 256},
                  "core": {"control_cyclic_offset": 72}}
        record_followup_result(self.tmp.name, self.digest, "pwncrash", {
            "query": "pwncrash", "selector": "", "binary_digest": self.digest,
            "status": "ok", "report": {**report, "input": {"kind": "file", "length": 256}},
        })
        unbound = rat._route_with_feedback(self.binary, {"imports": ["read"]}, None, None)
        self.assertFalse(any(item["status"] == "resolved" for item in unbound["feedback"]))
        record_followup_result(self.tmp.name, self.digest, "pwncrash", {
            "query": "pwncrash", "selector": "", "binary_digest": self.digest,
            "status": "ok", "report": report,
        })
        after = rat._route_with_feedback(self.binary, {"imports": ["read"]}, None, None)
        self.assertTrue(any(item["status"] == "resolved" for item in after["feedback"]))
        self.assertTrue(any("typed primitive PASS still requires direct SELF proof" in item
                            for item in after["unresolved"]))
        self.assertNotEqual(after["commitment"], "committed")

    def test_copy_relocation_coverage_boundaries(self):
        rat = _rat()
        profile = {"imports": ["read"], "facts": [], "binary_sha256": self.digest}
        args = SimpleNamespace(binary=self.binary, store=None, budget_bytes=16384,
                               format="json")
        for count in (31, 32, 33):
            with self.subTest(count=count), \
                 patch.object(rat, "_gather_profile", return_value=profile), \
                 patch.object(rat, "copy_relocations", return_value=(
                     [("0x%x" % i, "sym%d" % i, "COPY") for i in range(count)], None)), \
                 patch.object(rat, "_record_query_feedback"), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(rat.cmd_query_pwn(args), 0)
                doc = json.loads(output.getvalue())
            stats = doc["facts"]["copy_relocations_coverage"]
            self.assertEqual((stats["total"], stats["returned"], stats["omitted"]),
                             (count, min(count, 32), max(count - 32, 0)))
            self.assertEqual(doc["status"], "partial" if count > 32 else "ok")
            self.assertEqual(doc["coverage"]["complete"], count <= 32)

    def test_competing_pwn_followups_keep_both_leads_without_forced_decision(self):
        profile = {"imports": ["malloc", "free", "printf", "read"]}
        before = route(profile=profile, binary_digest=self.digest)
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        feedback = load_feedback(self.tmp.name, self.digest, before["next"])
        after = route(profile=profile, binary_digest=self.digest, probe_feedback=feedback)
        from ratlib.schema import validate
        validate(after, "rat.route-result/v2")
        self.assertEqual({item["query"] for item in after["next"]}, {"pwncrash", "decomp"})
        self.assertEqual(len(after["next"]), 3)
        self.assertIsNone(after["decision"])
        self.assertEqual(after["commitment"], "provisional")
        self.assertEqual({"heap-lifetime", "format-string", "stack-overwrite"}, set(after["leads"]))

    def test_pwn_followup_selects_recovered_format_caller(self):
        profile = {"imports": ["printf", "read"]}
        rev = {"functions": [{"name": "main", "calls": ["printf"]}]}
        before = route(profile=profile, revq=rev, binary_digest=self.digest)
        record_query_result(self.tmp.name, self.digest, _pwn_card(self.digest))
        feedback = load_feedback(self.tmp.name, self.digest, before["next"])
        after = route(profile=profile, revq=rev, binary_digest=self.digest, probe_feedback=feedback)
        self.assertIn("<bin> main", [item["target"] for item in after["next"]
                                      if item["query"] == "decomp"])

    def test_frontdoor_route_pwn_query_route_reaches_runtime_probe(self):
        rat = _rat()
        profile = {"imports": ["read"], "facts": [], "binary_sha256": self.digest}
        rev = {"imports": [], "functions": [], "strings": [], "sha256": self.digest}
        mod = SimpleNamespace(compute_interesting=lambda _: [])
        args = SimpleNamespace(binary=self.binary, store=None, fast=True, format="json")
        qargs = SimpleNamespace(**vars(args), budget_bytes=16384)
        with patch.object(rat, "_doctor_capabilities", return_value={"angr": False}), \
             patch.object(rat, "_gather_profile", return_value=profile), \
             patch.object(rat, "_gather_revq", return_value=(mod, rev)), \
             patch.object(rat, "_record_revq_invocation"), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(rat.cmd_route(args), 0)
            first = json.loads(output.getvalue().splitlines()[-1])
            output.seek(0); output.truncate(0)
            self.assertEqual(rat.cmd_query_pwn(qargs), 0)
            output.seek(0); output.truncate(0)
            self.assertEqual(rat.cmd_route(args), 0)
            last = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(first["decision"]["action"], "rat query pwn")
        self.assertEqual(last["decision"]["action"], "pwncrash")
        self.assertEqual(last["next"][0]["source_probe_id"], first["decision"]["probe_id"])
        self.assertEqual(last["feedback"][0]["status"], "partial")

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
