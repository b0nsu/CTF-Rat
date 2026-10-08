import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.state_v2 import (
    Stream,
    revise_primitive,
    primitive_proof_contract,
    validate_history,
)
from tests.direct_evidence_helper import (
    CANONICAL_ENVIRONMENT,
    CANONICAL_SUBJECT,
    direct_evidence_envelope,
)


def direct_observation(stream, oid, kind):
    digest = direct_evidence_envelope(
        root=stream.root,
        producer="gdbq",
        measurement=("measurement:" + oid).encode(),
        summary=kind,
    )
    stream.append("observation.recorded", {
        "observation_id": oid,
        "kind": kind,
        "quality": {"level": "direct"},
        "validity": {"state": "active"},
        "evidence": [digest],
    })


def primitive_doc(primitive_id, cls, status, evidence, revision):
    return {
        "primitive_id": primitive_id,
        "class": cls,
        "status": status,
        "self_evidence": evidence,
        "input_digest": CANONICAL_SUBJECT,
        "environment_digest": CANONICAL_ENVIRONMENT,
        "revision": revision,
    }


class PrimitiveProofContractTests(unittest.TestCase):
    def test_control_flow_contract_is_explicit_and_versioned(self):
        contract = primitive_proof_contract("control-flow")
        self.assertEqual(contract["version"], "control-flow/v2")
        self.assertEqual(
            set(contract["slots"]),
            {"control-state", "attacker-marker", "control-target"},
        )
        self.assertIsNone(primitive_proof_contract("legacy-custom"))

    def test_control_flow_pass_requires_semantic_slot_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            direct_observation(stream, "obs_reg", "pwn.reg")
            direct_observation(stream, "obs_marker", "pwn.marker")
            direct_observation(stream, "obs_target", "pwn.control-target")
            revise_primitive(
                stream,
                primitive_doc("p", "control-flow", "candidate", [], 1),
            )
            with self.assertRaisesRegex(ValueError, "missing proof slots: control-target"):
                revise_primitive(stream, primitive_doc("p", "control-flow", "pass",
                                                     ["obs_reg", "obs_marker", "obs_target"], 2))

    def test_three_direct_measurements_of_same_fact_do_not_satisfy_contract(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            for oid in ("r1", "r2", "r3"):
                direct_observation(stream, oid, "pwn.reg")
            revise_primitive(
                stream,
                primitive_doc("p", "control-flow", "candidate", [], 1),
            )
            with self.assertRaisesRegex(
                ValueError, "missing proof slots: attacker-marker, control-target"
            ):
                revise_primitive(
                    stream,
                    primitive_doc(
                        "p", "control-flow", "pass", ["r1", "r2", "r3"], 2
                    ),
                )

    def test_solution_reconstruction_has_distinct_rev_contract(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            direct_observation(stream, "input", "rev.solution.input")
            direct_observation(stream, "oracle", "rev.solution.oracle")
            direct_observation(stream, "replay", "rev.solution.replay")
            revise_primitive(
                stream,
                primitive_doc(
                    "revp", "solution-reconstruction", "candidate", [], 1
                ),
            )
            with self.assertRaisesRegex(ValueError, "missing proof slots"):
                revise_primitive(stream, primitive_doc("revp", "solution-reconstruction", "pass",
                                                     ["input", "oracle", "replay"], 2))

    def test_unknown_legacy_class_keeps_generic_three_direct_gate(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            for oid in ("x1", "x2", "x3"):
                direct_observation(stream, oid, "legacy.unspecified")
            revise_primitive(
                stream,
                primitive_doc("legacy", "legacy-custom", "candidate", [], 1),
            )
            revise_primitive(
                stream,
                primitive_doc(
                    "legacy",
                    "legacy-custom",
                    "pass",
                    ["x1", "x2", "x3"],
                    2,
                ),
            )
            passed = stream.view()["primitives"]["legacy"]
            self.assertEqual(passed["status"], "pass")
            self.assertNotIn("proof_contract", passed.get("extensions", {}))

    def test_pre_contract_canonical_history_without_declaration_still_replays(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            direct_observation(stream, "obs_reg", "pwn.reg")
            direct_observation(stream, "obs_marker", "pwn.marker")
            direct_observation(stream, "obs_target", "pwn.control-target")
            revise_primitive(
                stream,
                primitive_doc("p", "legacy-custom", "candidate", [], 1),
            )
            revise_primitive(
                stream,
                primitive_doc(
                    "p",
                    "legacy-custom",
                    "pass",
                    ["obs_reg", "obs_marker", "obs_target"],
                    2,
                ),
            )
            events = stream.read()
            for event in events:
                if event["type"] == "primitive.revised":
                    event["payload"]["class"] = "control-flow"
                    event["payload"].get("extensions", {}).pop("proof_contract", None)
            view = validate_history(events, root, artifact_root=stream.root)
            self.assertEqual(view["primitives"]["p"]["status"], "pass")

    def test_wrong_explicit_contract_version_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            direct_observation(stream, "obs_reg", "pwn.reg")
            direct_observation(stream, "obs_marker", "pwn.marker")
            direct_observation(stream, "obs_target", "pwn.offset")
            revise_primitive(
                stream,
                primitive_doc("p", "control-flow", "candidate", [], 1),
            )
            doc = primitive_doc(
                "p",
                "control-flow",
                "pass",
                ["obs_reg", "obs_marker", "obs_target"],
                2,
            )
            doc["extensions"] = {"proof_contract": "control-flow/v0"}
            with self.assertRaisesRegex(ValueError, "requires proof_contract control-flow/v2"):
                revise_primitive(stream, doc)


if __name__ == "__main__":
    unittest.main()
