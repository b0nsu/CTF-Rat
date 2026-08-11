import os, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.artifact import put_bytes
from ratlib.orchestration import GateError, _state, enter, finish_phase, rollback
from ratlib.state_v2 import Stream, revise_primitive

D = "sha256:" + "a" * 64


def observation(stream, observation_id):
    record = put_bytes(
        observation_id.encode(),
        kind="test-evidence",
        media_type="text/plain",
        logical_name=observation_id,
        root=stream.root,
        provenance={"evidence_policy": {"level": "direct", "promotion_allowed": True}},
    )
    return {
        "observation_id": observation_id,
        "quality": {"level": "direct"},
        "validity": {"state": "active"},
        "evidence": [record["digest"]],
    }


def advance(root, phase):
    enter(root, phase)
    finish_phase(root, phase)


class PhaseValidatorTests(unittest.TestCase):
    def passed_primitive(self, root):
        stream = Stream(root)
        for observation_id in ("o1", "o2", "o3"):
            stream.append("observation.recorded", observation(stream, observation_id))
        primitive = {
            "primitive_id": "p",
            "input_digest": D,
            "environment_digest": D,
        }
        revise_primitive(stream, {**primitive, "status": "candidate", "self_evidence": []})
        revise_primitive(stream, {**primitive, "status": "pass", "self_evidence": ["o1", "o2", "o3"]})

    def to_p3(self, root):
        for phase in ("solve-P0", "solve-P1", "solve-P2"):
            advance(root, phase)
        enter(root, "solve-P3")

    def test_phase_exit_is_required_and_p4_is_unavailable(self):
        with tempfile.TemporaryDirectory() as root:
            enter(root, "solve-P0")
            with self.assertRaises(GateError):
                enter(root, "solve-P1")
            finish_phase(root, "solve-P0")
            advance(root, "solve-P1")
            advance(root, "solve-P2")
            enter(root, "solve-P3")
            finish_phase(root, "solve-P3")
            self.passed_primitive(root)
            with self.assertRaisesRegex(GateError, "automated execution ends after solve-P3"):
                enter(root, "solve-P4")

    def test_terminal_p3_requires_primitive_and_records_handoff(self):
        with tempfile.TemporaryDirectory() as root:
            self.to_p3(root)
            with self.assertRaisesRegex(GateError, "requires an active primitive PASS"):
                finish_phase(root, "solve-P3", terminal=True)
            self.passed_primitive(root)
            finish_phase(root, "solve-P3", terminal=True)
            self.assertIsNone(_state(root))
            handoffs = [event for event in Stream(root).read() if event["type"] == "operator.handoff.required"]
            self.assertEqual(["p"], handoffs[-1]["payload"]["primitive_ids"])

    def test_rollback_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            advance(root, "solve-P0")
            enter(root, "solve-P1")
            self.assertTrue(rollback(root, "solve-P0", "bad evidence", ["o"]))
            self.assertEqual("solve-P0", _state(root))
            self.assertEqual({}, Stream(root).view()["observations"])
