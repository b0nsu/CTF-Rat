import importlib.machinery
import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))

from ratlib.artifact import put_bytes
from ratlib.metrics import route_assessment_metrics
from ratlib.state_v2 import Stream
from tests.direct_evidence_helper import direct_evidence_envelope


def load_rat():
    loader = importlib.machinery.SourceFileLoader("rat_skill_under_test", str(BIN / "rat"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


RAT = load_rat()


def route_result():
    return {
        "decision": {"action": "rat query pwn", "target": "x", "evidence": ["overflow-imports"], "rule": "x"},
        "commitment": "provisional",
        "leads": ["stack-overwrite"],
        "skill": None,
        "dimensions": {
            "vulnerability_surfaces": ["stack-overwrite-candidate"],
            "program_shapes": [],
            "obstacles": [],
            "constraints": [],
        },
        "unresolved": ["prove PC control"],
    }


def observation(stream, observation_id, kind, *, direct=True):
    if direct:
        digest = direct_evidence_envelope(
            root=stream.root,
            producer="gdbq",
            measurement=("measurement:" + observation_id).encode(),
            summary=observation_id,
        )
    else:
        digest = put_bytes(
            ("heuristic:" + observation_id).encode(),
            kind="test-evidence",
            media_type="text/plain",
            logical_name=observation_id + ".txt",
            root=stream.root,
        )["digest"]
    doc = {
        "schema": "rat.observation/v1",
        "observation_id": observation_id,
        "run_id": "run_skill",
        "created_at": "2026-01-01T00:00:00+00:00",
        "producer": {"tool": "test"},
        "subject": {"kind": "binary"},
        "kind": kind,
        "value": {"confirmed": True},
        "evidence": [digest],
        "quality": {"level": "direct" if direct else "heuristic"},
        "validity": {"state": "active"},
    }
    stream.append("observation.recorded", doc)
    return doc


class RouteSkillAssessmentTests(unittest.TestCase):
    def test_direct_matching_observation_commits_skill_and_metrics_see_first_skill(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            observation(stream, "obs_pc", "pwn.reg")
            result = route_result()

            evidence_ids, reason = RAT._select_route_skill(
                root, result, "pwn-stack", ["obs_pc"], "runtime PC/register evidence confirms stack path"
            )
            RAT._record_route_assessment(
                root, "route", result,
                skill_evidence_observation_ids=evidence_ids,
                skill_reason=reason,
            )

            self.assertEqual(result["skill"], "pwn-stack")
            self.assertEqual(result["commitment"], "committed")
            note = stream.read()[-1]["payload"]
            self.assertEqual(note["kind"], "route-assessment")
            self.assertEqual(note["skill"], "pwn-stack")
            self.assertEqual(note["skill_evidence_observation_ids"], ["obs_pc"])
            self.assertEqual(note["skill_reason"], "runtime PC/register evidence confirms stack path")
            self.assertEqual(route_assessment_metrics(root)["first_skill"], "pwn-stack")

    def test_canonical_proof_kinds_can_commit_matching_skills(self):
        cases = [
            ("pwn.memory-control", "pwn-stack"),
            ("pwn.control-target", "pwn-rop"),
            ("rev.solution.oracle", "rev-checker"),
            ("rev.solution.input", "rev-symbolic"),
        ]
        for kind, skill in cases:
            with self.subTest(kind=kind, skill=skill), tempfile.TemporaryDirectory() as root:
                stream = Stream(root)
                observation(stream, "obs_proof", kind)
                result = route_result()
                evidence_ids, reason = RAT._select_route_skill(
                    root, result, skill, ["obs_proof"], "canonical proof observation"
                )
                self.assertEqual(evidence_ids, ["obs_proof"])
                self.assertEqual(reason, "canonical proof observation")
                self.assertEqual(result["skill"], skill)
                self.assertEqual(result["commitment"], "committed")

    def test_heuristic_observation_cannot_commit_skill(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            observation(stream, "obs_guess", "pwn.reg", direct=False)
            with self.assertRaisesRegex(ValueError, "derived/direct"):
                RAT._select_route_skill(
                    root, route_result(), "pwn-stack", ["obs_guess"], "guess"
                )

    def test_matching_quality_but_wrong_kind_cannot_commit_skill(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            observation(stream, "obs_pc", "pwn.reg")
            with self.assertRaisesRegex(ValueError, "does not support skill rev-vm"):
                RAT._select_route_skill(
                    root, route_result(), "rev-vm", ["obs_pc"], "wrong method"
                )

    def test_unknown_or_invalidated_observation_cannot_commit_skill(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            with self.assertRaisesRegex(ValueError, "unknown observation_id"):
                RAT._select_route_skill(
                    root, route_result(), "pwn-stack", ["missing"], "missing"
                )
            observation(stream, "obs_pc", "pwn.reg")
            stream.append("evidence.invalidated", {
                "observation_ids": ["obs_pc"], "reason": "measurement superseded"
            })
            with self.assertRaisesRegex(ValueError, "inactive observation_id"):
                RAT._select_route_skill(
                    root, route_result(), "pwn-stack", ["obs_pc"], "stale"
                )

    def test_skill_requires_evidence_and_reason(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "at least one"):
                RAT._select_route_skill(root, route_result(), "pwn-stack", [], "reason")
            with self.assertRaisesRegex(ValueError, "--skill-reason"):
                RAT._select_route_skill(root, route_result(), "pwn-stack", ["obs"], "")


if __name__ == "__main__":
    unittest.main()
