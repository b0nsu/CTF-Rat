"""Reuse is explicit, scoped, and never a new PASS or SOLVED claim."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.artifact import put_bytes
from ratlib.orchestration import (
    DEFAULT_BUDGET, GateError, enter, finish_phase, finish_task,
    invalidate, reusable_scout_result, start_task,
)
from ratlib.state_v2 import Stream
from tests.direct_evidence_helper import direct_evidence_envelope


def contract(role="static-scout", objective="inspect"):
    return {"schema": "rat.role-contract/v1", "role": role,
            "phase": "solve-P1" if role.endswith("scout") else "solve-P2",
            "objective": objective, "allowed_inputs": [],
            "required_outputs": ["analysis"], "forbidden_actions": [],
            "state_write_scope": [],
            "capabilities": {"network_write": False, "repository_write": False,
                             "evidence_promote": False},
            "budgets": dict(DEFAULT_BUDGET), "stop_conditions": ["budget"]}


class ScoutReuse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        enter(self.root, "solve-P0")
        finish_phase(self.root, "solve-P0")
        self.cp = enter(self.root, "solve-P1")["checkpoint_id"]
        self.stream = Stream(self.root)
        evidence = direct_evidence_envelope(root=self.stream.root, producer="gdbq",
                                            measurement=b"e0", summary="e0")
        self.stream.append("observation.recorded", {
            "observation_id": "e0",
            "quality": {"level": "direct"},
            "validity": {"state": "active"},
            "evidence": [evidence],
        })
        self.contract = contract()
        self.task = start_task(self.root, self.contract, checkpoint_id=self.cp,
                               inputs=["target"], dependencies=["e0"])
        self.artifact = put_bytes(b"bounded-scout-result", kind="scout-summary",
                                  media_type="text/plain", logical_name="scout.txt",
                                  root=self.stream.root)["digest"]
        self.output = {"schema": "rat.task-output/v1", "task_id": self.task["task_id"],
                       "status": "completed", "outputs": {"analysis": self.artifact},
                       "evidence_ids": ["e0"]}
        finish_task(self.root, self.task["task_id"], "completed", self.output)

    def lookup(self, **updates):
        options = {"checkpoint_id": self.cp, "inputs": ["target"],
                   "dependencies": ["e0"]}
        options.update(updates)
        return reusable_scout_result(self.root, self.contract, **options)

    def test_exact_completed_artifact_result_can_be_reused(self):
        events_before = len(self.stream.read())
        result = self.lookup()
        self.assertTrue(result["reused"])
        self.assertEqual(result["task_id"], self.task["task_id"])
        self.assertEqual(result["artifacts"]["analysis"], self.artifact)
        self.assertEqual(len(self.stream.read()), events_before)

    def test_no_reuse_for_other_inputs_checkpoint_or_contract(self):
        self.assertIsNone(self.lookup(inputs=["other"]))
        self.assertIsNone(self.lookup(dependencies=[]))
        self.assertIsNone(self.lookup(checkpoint_id="unknown"))
        self.assertIsNone(reusable_scout_result(
            self.root, contract(objective="new hypothesis"),
            checkpoint_id=self.cp, inputs=["target"], dependencies=["e0"]))

    def test_invalidated_self_evidence_rejects_reuse(self):
        invalidate(self.root, ["e0"], "counterexample")
        self.assertIsNone(self.lookup())

    def test_corrupted_artifact_rejects_reuse(self):
        name = self.artifact.split(":", 1)[1]
        path = os.path.join(self.stream.root, "objects", "sha256", name[:2], name[2:])
        with open(path, "wb") as file:
            file.write(b"tampered")
        self.assertIsNone(self.lookup())

    def test_invalidated_input_dependency_rejects_reuse(self):
        evidence = direct_evidence_envelope(root=self.stream.root, producer="gdbq",
                                            measurement=b"input", summary="input")
        self.stream.append("observation.recorded", {
            "observation_id": "input-evidence", "quality": {"level": "direct"},
            "validity": {"state": "active"}, "evidence": [evidence],
        })
        task = start_task(self.root, self.contract, checkpoint_id=self.cp,
                          inputs=["other"], dependencies=["input-evidence"])
        output = dict(self.output, task_id=task["task_id"])
        finish_task(self.root, task["task_id"], "completed", output)
        self.assertIsNotNone(self.lookup(inputs=["other"], dependencies=["input-evidence"]))
        invalidate(self.root, ["input-evidence"], "input premise refuted")
        self.assertIsNone(self.lookup(inputs=["other"], dependencies=["input-evidence"]))

    def test_rat_task_is_directly_executable(self):
        process = subprocess.run([os.path.join(ROOT, "bin", "rat-task"), "--help"],
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_non_scout_role_cannot_reuse(self):
        with self.assertRaises(GateError):
            reusable_scout_result(self.root, contract("hypothesis"),
                                  checkpoint_id=self.cp, inputs=["target"],
                                  dependencies=["e0"])

    def test_rat_task_reuse_exposes_read_only_lookup(self):
        contract_path = os.path.join(self.root, "contract.json")
        with open(contract_path, "w", encoding="utf-8") as file:
            json.dump(self.contract, file)
        cmd = [sys.executable, os.path.join(ROOT, "bin", "rat-task"),
               "--root", self.root, "reuse", "--contract", contract_path,
               "--checkpoint", self.cp, "--input", "target", "--depends", "e0"]
        process = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["task_id"], self.task["task_id"])
        process = subprocess.run(cmd[:-2] + ["--input", "different"],
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIsNone(json.loads(process.stdout))


if __name__ == "__main__":
    unittest.main()
