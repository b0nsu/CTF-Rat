import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import put_bytes
from ratlib.compact import budget_compact, estimate_tokens
from ratlib.state_v2 import Stream, revise_finding, revise_primitive

D = "sha256:" + "a" * 64

def observation(stream, oid):
    rec = put_bytes(oid.encode(), kind="test-evidence", media_type="text/plain", logical_name=oid,
                     root=stream.root, provenance={"evidence_policy": {"level": "direct", "promotion_allowed": True}})
    return {"observation_id": oid, "quality": {"level": "direct"}, "validity": {"state": "active"}, "evidence": [rec["digest"]]}

def seeded_stream(d):
    s = Stream(d)
    for oid in ("o1", "o2", "o3"):
        s.append("observation.recorded", observation(s, oid))
    revise_finding(s, {"finding_id": "f1", "state": "proposed", "evidence_observation_ids": []})
    revise_finding(s, {"finding_id": "f1", "state": "supported", "evidence_observation_ids": ["o1"]})
    revise_finding(s, {"finding_id": "f1", "state": "confirmed", "evidence_observation_ids": ["o1"]})
    revise_primitive(s, {"primitive_id": "p1", "status": "candidate", "self_evidence": [],
                          "input_digest": D, "environment_digest": D})
    revise_primitive(s, {"primitive_id": "p1", "status": "pass", "self_evidence": ["o1", "o2", "o3"],
                          "input_digest": D, "environment_digest": D})
    for i in range(5):
        s.append("hypothesis.recorded", {"hypothesis_id": "h%d" % i, "text": "hypothesis number %d" % i})
    for i in range(5):
        s.append("next.recorded", {"probe": "probe number %d" % i})
    for i in range(5):
        s.append("route.ruled_out", {"fingerprint": "r%d" % i, "text": "ruled out %d" % i})
    return s

class BudgetCompactUnit(unittest.TestCase):
    def test_no_budget_keeps_everything(self):
        view = {"findings": {"f": {"state": "confirmed"}}, "primitives": {}, "hypotheses": {"h1": {}},
                "next_probes": ["p1"], "ruled_out": {}}
        out = budget_compact(view)
        self.assertEqual(out["hypotheses"], {"h1": {}})
        self.assertFalse(out["truncated"])
        self.assertEqual(out["omitted_counts"], {})

    def test_invalidating_and_confirmed_and_pass_are_never_dropped(self):
        view = {
            "findings": {"bad": {"state": "invalidated"}, "good": {"state": "confirmed"}},
            "primitives": {"p": {"status": "pass"}},
            "hypotheses": {"h%d" % i: {"text": "x" * 200} for i in range(20)},
            "next_probes": [], "ruled_out": {},
        }
        out = budget_compact(view, budget_tokens=1)
        self.assertEqual(out["invalidating_findings"], {"bad": {"state": "invalidated"}})
        self.assertEqual(out["confirmed_findings"], {"good": {"state": "confirmed"}})
        self.assertEqual(out["pass_primitives"], {"p": {"status": "pass"}})
        self.assertEqual(out["hypotheses"], {})
        self.assertTrue(out["truncated"])
        self.assertEqual(out["omitted_counts"]["hypotheses"], 20)

    def test_droppable_tiers_keep_newest_first(self):
        view = {"findings": {}, "primitives": {},
                "hypotheses": {"old": {"text": "a" * 50}, "new": {"text": "b" * 50}},
                "next_probes": [], "ruled_out": {}}
        fixed = {"invalidating_findings": {}, "confirmed_findings": {}, "pass_primitives": {}}
        budget = estimate_tokens(fixed) + estimate_tokens({"text": "b" * 50})
        out = budget_compact(view, budget_tokens=budget)
        self.assertIn("new", out["hypotheses"])
        self.assertNotIn("old", out["hypotheses"])

    def test_same_view_and_budget_and_cursor_is_deterministic(self):
        view = {"findings": {"f": {"state": "confirmed"}}, "primitives": {},
                "hypotheses": {"h1": {}, "h2": {}}, "next_probes": ["a", "b"], "ruled_out": {"r": {}}}
        a = budget_compact(view, budget_tokens=50, cursor={"stream_id": "s", "seq": 3})
        b = budget_compact(view, budget_tokens=50, cursor={"stream_id": "s", "seq": 3})
        self.assertEqual(a, b)

class BudgetCompactAgainstRealStream(unittest.TestCase):
    def test_pass_primitive_and_confirmed_finding_survive_tiny_budget(self):
        with tempfile.TemporaryDirectory() as d:
            s = seeded_stream(d)
            out = budget_compact(s.view(), budget_tokens=5)
            self.assertIn("f1", out["confirmed_findings"])
            self.assertIn("p1", out["pass_primitives"])
            self.assertEqual(out["hypotheses"], {})
            self.assertEqual(out["next_probes"], [])
            self.assertEqual(out["ruled_out"], {})
            self.assertTrue(out["truncated"])

    def test_generous_budget_keeps_droppable_tiers_too(self):
        with tempfile.TemporaryDirectory() as d:
            s = seeded_stream(d)
            out = budget_compact(s.view(), budget_tokens=100000)
            self.assertEqual(len(out["hypotheses"]), 5)
            self.assertEqual(len(out["next_probes"]), 5)
            self.assertEqual(len(out["ruled_out"]), 5)
            self.assertFalse(out["truncated"])

if __name__ == "__main__":
    unittest.main()
