"""Regression tests for evidence-backed stuck-state continuation advice.

The governor issues advice only; real PASS/VERIFY checks live upstream.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.governor import recommend


class EvidenceBackedContinuation(unittest.TestCase):
    @staticmethod
    def event(event_type, **payload):
        return {"type": event_type, "payload": payload}

    def setUp(self):
        self.obs = self.event("observation.recorded", observation_id="o1",
                              kind="measured", value=1, evidence=["sha256:example"])
        self.unknown = self.event("unknown.recorded", unknown_id="u1",
                                  evidence_observation_ids=["o1"])
        self.passed = self.event("primitive.revised", primitive_id="p1",
                                 status="pass", self_evidence=["o1"],
                                 input_digest="input", environment_digest="env")

    def test_active_primitive_beats_unrelated_unknown_in_both_orders(self):
        for events in ([self.obs, self.unknown, self.passed],
                       [self.obs, self.passed, self.unknown]):
            with self.subTest(events=events):
                self.assertEqual(recommend(events),
                                 {"action": "focused-deep", "basis": ["primitive:p1"]})

    def test_environment_invalidation_precedes_primitive(self):
        environment = self.event("finding.revised", finding_id="env1",
                                 state="stale", **{"class": "env"},
                                 evidence_observation_ids=["o1"])
        result = recommend([self.obs, self.unknown, self.passed, environment])
        self.assertEqual(result, {"action": "verify-environment", "basis": ["finding:env1"]})

    def test_refutation_precedes_unknown_discriminator(self):
        refuted = self.event("finding.revised", finding_id="f1", state="refuted",
                             evidence_observation_ids=["o1"])
        result = recommend([self.obs, self.unknown, refuted])
        self.assertEqual(result["action"], "re-route")
        self.assertEqual(result["basis"], ["finding:f1"])

    def test_ruled_out_route_precedes_unknown_discriminator(self):
        ruled = self.event("route.ruled_out", fingerprint="r1",
                           evidence_observation_ids=["o1"])
        self.assertEqual(recommend([self.obs, self.unknown, ruled])["action"], "re-route")

    def test_discriminator_when_only_active_unknown_remains(self):
        self.assertEqual(recommend([self.obs, self.unknown]),
                         {"action": "low-cost-discriminator", "basis": ["observation:o1"]})

    def test_pass_without_recorded_evidence_is_not_promoted(self):
        self.assertEqual(recommend([self.passed])["action"], "re-route-or-deep-escalate")

    def test_invalidated_pass_cannot_override_unrelated_active_unknown(self):
        other = self.event("observation.recorded", observation_id="o2",
                           kind="measured", value=2, evidence=["sha256:other"])
        remaining = self.event("unknown.recorded", unknown_id="u2",
                                evidence_observation_ids=["o2"])
        invalid = self.event("evidence.invalidated", observation_ids=["o1"],
                             reason="counterexample")
        result = recommend([self.obs, self.passed, self.unknown, other, remaining, invalid])
        self.assertEqual(result,
                         {"action": "low-cost-discriminator", "basis": ["observation:o2"]})

    def test_invalidated_unknown_does_not_keep_probing(self):
        invalid = self.event("evidence.invalidated", observation_ids=["o1"],
                             reason="counterexample")
        self.assertEqual(recommend([self.obs, self.unknown, invalid])["action"],
                         "re-route-or-deep-escalate")

    def test_consumed_primitive_remains_focus_candidate(self):
        consumed = self.event("primitive.consumed", primitive_id="p1",
                               input_digest="input", environment_digest="env")
        self.assertEqual(recommend([self.obs, self.passed, consumed])["action"], "focused-deep")


if __name__ == "__main__":
    unittest.main()
