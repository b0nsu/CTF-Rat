import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from ratlib.artifact import put_bytes
from ratlib.state_v2 import Stream
from tests.direct_evidence_helper import direct_evidence_envelope, CANONICAL_SUBJECT, CANONICAL_ENVIRONMENT


PKSHARE = ROOT / "bin" / "pkshare"
CHECK = ROOT / "bin" / "writeupcheck"
DIGEST = "sha256:" + "a" * 64


class WriteupPipelineTests(unittest.TestCase):
    def run_pkshare(self, directory, *args, check=True):
        return subprocess.run(
            [str(PKSHARE), *args], cwd=directory, text=True, capture_output=True, check=check
        )

    def write_state(self, directory, events):
        pathlib.Path(directory, "STATE.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in events)
        )

    def complete_v2(self, directory, duplicate_self_evidence=False):
        stream = Stream(directory)
        observation_ids = []
        evidence_digests = []
        for number in range(3):
            observation_id = "obs%d" % number
            evidence_digest = direct_evidence_envelope(
                root=stream.root, producer="gdbq", measurement=b"measurement:" + observation_id.encode(),
                summary=observation_id)
            stream.append(
                "observation.recorded",
                {"observation_id": observation_id, "quality": {"level": "direct"},
                 "validity": {"state": "active"}, "evidence": [evidence_digest]},
            )
            observation_ids.append(observation_id)
            evidence_digests.append(evidence_digest)
        primitive = {
            "schema": "rat.primitive/v1", "primitive_id": "control", "name": "RIP control",
            "class": "control", "status": "candidate", "input_digest": CANONICAL_SUBJECT,
            "environment_digest": CANONICAL_ENVIRONMENT, "self_evidence": [],
            "constraints": [], "side_effects": [], "remote_equivalent": False,
            "producer": {"tool": "test"}, "revision": 1,
            "extensions": {"reproduction_command": "python3 solve_local.py", "marker_evidence": "RIP=0x41414141"},
        }
        stream.append("primitive.revised", primitive)
        selected_evidence = [observation_ids[0]] * 3 if duplicate_self_evidence else observation_ids
        primitive = dict(primitive, status="pass", self_evidence=selected_evidence, revision=2)
        stream.append("primitive.revised", primitive)
        pathlib.Path(directory, "solve_local.py").write_text("print('local evidence')\n")
        return stream, evidence_digests

    def write_attestation(self, directory, evidence):
        path = pathlib.Path(directory, "attestation.json")
        path.write_text(json.dumps({
            "schema": "rat.writeup-attestation/v1", "operator": "test-operator",
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
            "result": "local result independently confirmed", "evidence": [evidence],
        }))
        return path

    def test_flag_word_does_not_infer_solved(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_state(directory, [{"t": "init", "chal": "fixture"}, {"t": "ok", "text": "supplied fake flag file inspected locally"}])
            self.run_pkshare(directory)
            text = pathlib.Path(directory, "HANDOFF.md").read_text()
            self.assertIn("`ANALYZING`", text)
            self.assertFalse(pathlib.Path(directory, "WRITEUP.md").exists())

    def test_legacy_pass_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_state(directory, [{"t": "primitive", "name": "rip", "status": "pass", "evidence": "old note"}])
            self.run_pkshare(directory)
            text = pathlib.Path(directory, "HANDOFF.md").read_text()
            self.assertIn("`BLOCKED`", text)
            self.assertIn("LEGACY CANDIDATE", text)
            self.assertNotIn("`PRIMITIVE_PASS`", text)

    def test_v2_pass_is_authoritative_and_strict_lint_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            self.complete_v2(directory)
            self.run_pkshare(directory)
            text = pathlib.Path(directory, "HANDOFF.md").read_text()
            self.assertIn("`PRIMITIVE_PASS`", text)
            checked = subprocess.run([str(CHECK), "HANDOFF.md", "--strict"], cwd=directory, text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_duplicate_self_evidence_cannot_publish_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            # The stream is now the lifecycle authority: invalid PASS input
            # is rejected before a downstream writeup consumer can see it.
            with self.assertRaisesRegex(ValueError, "distinct active direct SELF"):
                self.complete_v2(directory, duplicate_self_evidence=True)

    def test_v2_invalidation_removes_publishable_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            stream, _ = self.complete_v2(directory)
            self.run_pkshare(directory)
            stream.append("evidence.invalidated", {"observation_ids": ["obs0"], "reason": "test invalidation"})
            self.run_pkshare(directory, "--force")
            text = pathlib.Path(directory, "HANDOFF.md").read_text()
            self.assertIn("`BLOCKED`", text)
            self.assertIn("BLOCKED/STALE", text)
            self.assertNotIn("`PRIMITIVE_PASS`", text)

    def test_invalidated_evidence_cannot_support_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            stream, evidence = self.complete_v2(directory)
            stream.append("evidence.invalidated", {"observation_ids": ["obs0"], "reason": "test invalidation"})
            attestation = self.write_attestation(directory, evidence[0])
            result = self.run_pkshare(directory, "--solved", "--attestation", str(attestation), check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("unavailable evidence", result.stderr)

    def test_corrupt_evidence_cannot_publish_or_support_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            _, evidence = self.complete_v2(directory)
            digest_hex = evidence[0][7:]
            object_path = pathlib.Path(directory, ".rat", "objects", "sha256", digest_hex[:2], digest_hex[2:])
            object_path.write_bytes(b"corrupt")
            self.run_pkshare(directory)
            text = pathlib.Path(directory, "HANDOFF.md").read_text()
            self.assertIn("`BLOCKED`", text)
            self.assertIn("available_evidence_artifacts", text)
            attestation = self.write_attestation(directory, evidence[0])
            result = self.run_pkshare(directory, "--solved", "--attestation", str(attestation), check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("unavailable evidence", result.stderr)

    def test_completed_modes_require_matching_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            _, evidence = self.complete_v2(directory)
            missing = self.run_pkshare(directory, "--solved", check=False)
            self.assertEqual(missing.returncode, 2)
            attestation = self.write_attestation(directory, evidence[0])
            self.run_pkshare(directory, "--solved", "--attestation", str(attestation))
            text = pathlib.Path(directory, "WRITEUP.md").read_text()
            self.assertIn("`OPERATOR_COMPLETED`", text)
            checked = subprocess.run([str(CHECK), "WRITEUP.md", "--strict"], cwd=directory, text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_attestation_rejects_unknown_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            self.complete_v2(directory)
            attestation = self.write_attestation(directory, "sha256:" + "f" * 64)
            result = self.run_pkshare(directory, "--submission", "--attestation", str(attestation), check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("unavailable evidence", result.stderr)

    def test_attestation_rejects_unmaterialized_primitive_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            self.complete_v2(directory)
            attestation = self.write_attestation(directory, DIGEST)
            result = self.run_pkshare(directory, "--solved", "--attestation", str(attestation), check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("unavailable evidence", result.stderr)

    def test_existing_output_requires_force(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_state(directory, [{"t": "init", "chal": "fixture"}])
            self.run_pkshare(directory)
            result = self.run_pkshare(directory, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("refusing to overwrite", result.stderr)

    def test_malformed_legacy_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            pathlib.Path(directory, "STATE.jsonl").write_text('{"t":"init"}\nnot-json\n')
            result = self.run_pkshare(directory, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(pathlib.Path(directory, "HANDOFF.md").exists())

    def test_lint_rejects_placeholder_and_status_claim_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            self.complete_v2(directory)
            self.run_pkshare(directory)
            path = pathlib.Path(directory, "HANDOFF.md")
            path.write_text(path.read_text() + "\nSOLVED ✅ <fill this>\n")
            checked = subprocess.run([str(CHECK), "HANDOFF.md"], cwd=directory, text=True, capture_output=True)
            self.assertEqual(checked.returncode, 1)
            self.assertIn("solve/submission claim", checked.stdout)
            self.assertIn("placeholder text remains", checked.stdout)


if __name__ == "__main__":
    unittest.main()
