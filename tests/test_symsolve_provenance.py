import importlib.machinery
import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)

from ratlib.artifact import get
from ratlib import completion
from ratlib.completion import _symbolic_engine_issue
from ratlib.state_v2 import Stream, revise_primitive
from tests.direct_evidence_helper import CANONICAL_ENVIRONMENT, direct_evidence_envelope


def load_symsolve():
    path = os.path.join(ROOT, "solve", "_template", "rev", "symsolve.py")
    loader = importlib.machinery.SourceFileLoader("symsolve_provenance_test", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class SymsolveProvenanceTests(unittest.TestCase):
    def test_concrete_success_records_engine_provenance_for_completion_gate(self):
        symsolve = load_symsolve()
        with tempfile.TemporaryDirectory() as root:
            binary = os.path.join(root, "subject.bin")
            with open(binary, "wb") as target:
                target.write(b"fixture binary")

            observation_id = symsolve.record_concrete_observation(
                root, binary, b"verified marker", {"stdin": "4142"})
            view = Stream(root).view()
            observation = view["observations"][observation_id]
            self.assertEqual(observation["kind"], "rev.symsolve.concrete-verify")
            self.assertEqual(observation["producer"]["engine"], "symsolve")
            self.assertRegex(observation["producer"]["engine_build_digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(observation["quality"]["level"], "heuristic")
            capture = json.loads(get(observation["evidence"][0], root=Stream(root).root))
            self.assertEqual(capture["output_hex"], b"verified marker".hex())

            primitives = view["primitives"]
            self.assertEqual(len(primitives), 1)
            primitive = next(iter(primitives.values()))
            self.assertEqual(primitive["status"], "candidate")
            self.assertEqual(primitive["input_digest"], observation["subject"]["sha256"])
            self.assertEqual(primitive["producer"]["engine"], "symsolve")
            self.assertEqual(primitive["extensions"]["solve_origin"], "rev-symbolic")
            self.assertEqual(primitive["extensions"]["engine_observation_id"], observation_id)
            self.assertIsNone(_symbolic_engine_issue(primitive, view))

    def test_concrete_success_attaches_provenance_to_existing_pass(self):
        symsolve = load_symsolve()
        with tempfile.TemporaryDirectory() as root:
            binary = os.path.join(root, "subject.bin")
            with open(binary, "wb") as target:
                target.write(b"fixture binary")
            binary_digest = "sha256:" + hashlib.sha256(b"fixture binary").hexdigest()

            stream = Stream(root)
            self_evidence = []
            for index in range(3):
                evidence = direct_evidence_envelope(
                    root=stream.root,
                    producer="gdbq",
                    measurement=("independent measurement %d" % index).encode(),
                    subject_digest=binary_digest,
                )
                observation_id = "obs_direct_%d" % index
                stream.append("observation.recorded", {
                    "observation_id": observation_id,
                    "quality": {"level": "direct"},
                    "validity": {"state": "active"},
                    "evidence": [evidence],
                })
                self_evidence.append(observation_id)

            candidate = {
                "primitive_id": "prim_existing",
                "status": "candidate",
                "self_evidence": [],
                "input_digest": binary_digest,
                "environment_digest": CANONICAL_ENVIRONMENT,
            }
            revise_primitive(stream, candidate)
            revise_primitive(stream, {
                **candidate, "status": "pass", "self_evidence": self_evidence,
            })
            before = stream.view()["primitives"]["prim_existing"]

            observation_id = symsolve.record_concrete_observation(
                root, binary, b"verified marker", {"stdin": "4142"})

            primitive = Stream(root).view()["primitives"]["prim_existing"]
            self.assertEqual(primitive["status"], "pass")
            self.assertEqual(primitive["self_evidence"], self_evidence)
            self.assertEqual(primitive["revision"], before["revision"] + 1)
            self.assertEqual(primitive["producer"]["engine"], "symsolve")
            self.assertEqual(primitive["extensions"]["solve_origin"], "rev-symbolic")
            self.assertEqual(primitive["extensions"]["engine_observation_id"], observation_id)

    def test_plaintext_state_append_can_forge_sanctioned_observation(self):
        """Document the unsigned local STATE trust boundary with an executable case."""
        with tempfile.TemporaryDirectory() as root:
            subject_digest = "sha256:" + "a" * 64
            environment_digest = "sha256:" + "b" * 64
            report_digest = "sha256:" + "c" * 64
            report_build_digest = "sha256:" + "d" * 64
            identity = load_symsolve().engine_identity()
            encoded_identity = {**identity, "harness_sha256": identity["harness_sha256"].removeprefix("sha256:")}
            engine_digest = "sha256:" + hashlib.sha256(json.dumps(encoded_identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            observation_id = "obs_forged_plaintext"
            task_id = "task_forged_plaintext"
            primitive_id = "prim_forged_plaintext"
            verification_id = "verify_forged_plaintext"
            observation = {
                "schema": "rat.observation/v1", "observation_id": observation_id,
                "run_id": "run_local", "created_at": "2026-09-24T12:00:00+00:00",
                "producer": {"tool": "symsolve", "engine": "symsolve",
                             "engine_build_digest": engine_digest, "engine_identity": identity},
                "subject": {"kind": "binary", "sha256": subject_digest},
                "kind": "rev.symsolve.concrete-verify",
                "value": {"verdict": "pass", "engine": "symsolve",
                          "engine_build_digest": engine_digest},
                "evidence": [report_digest], "quality": {"level": "heuristic"},
                "validity": {"state": "active"},
            }
            primitive = {
                "schema": "rat.primitive/v1", "primitive_id": primitive_id,
                "name": "forged symbolic solution", "class": "solution-reconstruction",
                "status": "pass", "input_digest": subject_digest,
                "environment_digest": environment_digest, "self_evidence": [],
                "constraints": [], "side_effects": [], "remote_equivalent": False,
                "producer": {"tool": "manual", "version": "1"}, "revision": 1,
                "extensions": {"engine_observation_id": observation_id},
            }
            record = {
                "verification_id": verification_id, "report_digest": report_digest,
                "verdict": "pass", "environment_match": True,
                "exploit_task_id": task_id, "primitive_id": primitive_id,
                "producer_build_digest": report_build_digest,
            }
            events = []
            for seq, event_type, payload in (
                (1, "observation.recorded", observation),
                (2, "primitive.revised", primitive),
                (3, "verification.recorded", record),
            ):
                events.append({
                    "schema": "rat.state-event/v2", "stream_id": "stream_forged",
                    "seq": seq, "event_id": "event_%d" % seq,
                    "at": "2026-09-24T12:00:00+00:00", "actor": "local",
                    "task_id": "local", "type": event_type, "payload": payload,
                    "caused_by": [],
                })
            state_path = Stream(root).path
            os.makedirs(os.path.dirname(state_path), exist_ok=True)
            with open(state_path, "w", encoding="utf-8") as target:
                target.write("".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
                                   for event in events))

            report = {
                "verdict": "pass", "environment_match": True,
                "provenance": {
                    "primitive_id": primitive_id, "exploit_task_id": task_id,
                    "environment_digest": environment_digest,
                },
                "producer": {"build_digest": report_build_digest},
            }
            task = {
                "phase": "solve-P4", "role": "exploit-builder", "status": "completed",
                "primitive_id": primitive_id, "input_digest": subject_digest,
                "environment_digest": environment_digest,
            }
            with patch.object(completion, "_verification_report", return_value=report), \
                 patch.object(completion, "_task", return_value=(task, "/task")):
                result = completion.completion_gate(root)

            # Plain JSONL edits are accepted by this single-checkout trust model;
            # the gate can validate structure but cannot prove who wrote it.
            self.assertTrue(result["verified"])
            self.assertEqual(result["reason"], "verified")


if __name__ == "__main__":
    unittest.main()
