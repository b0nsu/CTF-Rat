import importlib.machinery
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)

from ratlib import completion


def load_ratbench():
    loader = importlib.machinery.SourceFileLoader("_ratbench_p0_test", os.path.join(BIN, "ratbench"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _FakeStream:
    def __init__(self, events, primitives, observations=None, notes=None):
        self._events = events
        self._primitives = primitives
        self._observations = observations or {}
        self._notes = notes or []

    def read(self):
        return list(self._events)

    def view(self):
        return {"primitives": dict(self._primitives), "observations": dict(self._observations),
                "notes": list(self._notes)}


class CompletionGateTests(unittest.TestCase):
    def setUp(self):
        self.primitive = {
            "primitive_id": "prim_1",
            "status": "pass",
            "input_digest": "sha256:" + "a" * 64,
            "environment_digest": "sha256:" + "b" * 64,
        }
        self.record = {
            "verification_id": "verify_1",
            "report_digest": "sha256:" + "c" * 64,
            "verdict": "pass",
            "environment_match": True,
            "exploit_task_id": "task_1",
            "primitive_id": "prim_1",
            "producer_build_digest": "sha256:" + "d" * 64,
        }
        self.report = {
            "verdict": "pass",
            "environment_match": True,
            "provenance": {
                "primitive_id": "prim_1",
                "exploit_task_id": "task_1",
                "environment_digest": self.primitive["environment_digest"],
            },
            "producer": {"build_digest": self.record["producer_build_digest"]},
        }
        self.task = {
            "phase": "solve-P4", "role": "exploit-builder", "status": "completed",
            "primitive_id": "prim_1", "input_digest": self.primitive["input_digest"],
            "environment_digest": self.primitive["environment_digest"],
        }

    def test_primitive_pass_alone_is_not_a_verified_solve(self):
        fake = _FakeStream([], {"prim_1": self.primitive})
        with patch.object(completion, "Stream", return_value=fake):
            result = completion.completion_gate("/challenge")
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "no-active-verification")

    def test_linked_authenticated_verification_promotes_solve(self):
        events = [{"type": "verification.recorded", "payload": self.record}]
        fake = _FakeStream(events, {"prim_1": self.primitive})
        with patch.object(completion, "Stream", return_value=fake), \
             patch.object(completion, "_verification_report", return_value=self.report), \
             patch.object(completion, "_task", return_value=(self.task, "/task")):
            result = completion.completion_gate("/challenge")
        self.assertTrue(result["verified"])
        self.assertEqual(result["primitive_id"], "prim_1")

    def test_pass_revision_cannot_inherit_prior_verification(self):
        primitive = {**self.primitive, "revision": 3}
        record = {**self.record, "primitive_revision": 2}
        fake = _FakeStream([{"type": "verification.recorded", "payload": record}],
                           {"prim_1": primitive})
        with patch.object(completion, "Stream", return_value=fake):
            result = completion.completion_gate("/challenge")
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "no-active-verification")

    def test_legacy_verification_cannot_survive_later_revision(self):
        events = [
            {"seq": 2, "type": "verification.recorded", "payload": self.record},
            {"seq": 3, "type": "primitive.revised", "payload": {"primitive_id": "prim_1"}},
        ]
        fake = _FakeStream(events, {"prim_1": self.primitive})
        with patch.object(completion, "Stream", return_value=fake):
            result = completion.completion_gate("/challenge")
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "no-active-verification")

    def test_staled_verification_does_not_count(self):
        events = [
            {"type": "verification.recorded", "payload": self.record},
            {"type": "verification.staled", "payload": {"verification_id": "verify_1"}},
        ]
        fake = _FakeStream(events, {"prim_1": self.primitive})
        with patch.object(completion, "Stream", return_value=fake):
            result = completion.completion_gate("/challenge")
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "no-active-verification")

    def _symbolic_fixture(self, observation=None, engine=None, attestation=None,
                          *, tagged=True, primitive_class="control-flow", notes=None):
        primitive = dict(self.primitive)
        primitive["class"] = primitive_class
        primitive["extensions"] = {"solve_origin": "rev-symbolic"} if tagged else {}
        primitive["producer"] = {"tool": "manual-review", "version": "1"}
        if engine:
            primitive["producer"].update({"engine": engine, "engine_build_digest": "sha256:" + "e" * 64})
        observations = {}
        if observation:
            primitive["extensions"]["engine_observation_id"] = observation["observation_id"]
            observations[observation["observation_id"]] = observation
        if attestation:
            primitive["extensions"]["operator_attestation"] = attestation
        events = [{"type": "verification.recorded", "payload": self.record}]
        return _FakeStream(events, {"prim_1": primitive}, observations, notes)

    def _sanctioned_observation(self):
        harness = os.path.join(ROOT, "solve", "_template", "rev", "symsolve.py")
        identity = {
            "harness_sha256": "sha256:" + hashlib.sha256(Path(harness).read_bytes()).hexdigest(),
            "packages": {"angr": "test", "unicorn": "test"},
            "python": "3.12.0", "engine": "native-unicorn",
        }
        encoded = {**identity, "harness_sha256": identity["harness_sha256"].removeprefix("sha256:")}
        digest = "sha256:" + hashlib.sha256(json.dumps(encoded, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {
            "schema": "rat.observation/v1", "observation_id": "obs_symsolve_1",
            "kind": "rev.symsolve.concrete-verify", "quality": {"level": "heuristic"},
            "validity": {"state": "active"},
            "subject": {"kind": "binary", "sha256": self.primitive["input_digest"]},
            "value": {"verdict": "pass", "engine": "symsolve", "engine_build_digest": digest},
            "producer": {"tool": "symsolve", "engine": "symsolve", "engine_build_digest": digest,
                         "engine_identity": identity},
            "evidence": [self.record["report_digest"]],
        }

    def _run_symbolic_gate(self, fake):
        with patch.object(completion, "Stream", return_value=fake), \
             patch.object(completion, "_verification_report", return_value=self.report), \
             patch.object(completion, "_task", return_value=(self.task, "/task")):
            return completion.completion_gate("/challenge")

    def test_rev_symbolic_observation_fallback_is_authoritative(self):
        result = self._run_symbolic_gate(
            self._symbolic_fixture(observation=self._sanctioned_observation()))
        self.assertTrue(result["verified"])
        self.assertNotIn("advisory", result)

    def test_unlisted_symsolve_harness_is_denied(self):
        observation = self._sanctioned_observation()
        identity = observation["producer"]["engine_identity"]
        identity["harness_sha256"] = "sha256:" + "f" * 64
        encoded = {**identity, "harness_sha256": "f" * 64}
        digest = "sha256:" + hashlib.sha256(json.dumps(encoded, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        observation["producer"]["engine_build_digest"] = digest
        observation["value"]["engine_build_digest"] = digest
        result = self._run_symbolic_gate(self._symbolic_fixture(observation=observation))
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_mismatched_symsolve_engine_identity_is_denied(self):
        observation = self._sanctioned_observation()
        observation["producer"]["engine_build_digest"] = "sha256:" + "e" * 64
        observation["value"]["engine_build_digest"] = "sha256:" + "e" * 64
        result = self._run_symbolic_gate(self._symbolic_fixture(observation=observation))
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_rev_symbolic_without_sanctioned_observation_is_denied_by_default(self):
        result = self._run_symbolic_gate(self._symbolic_fixture())
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_untagged_solution_reconstruction_without_observation_is_denied(self):
        # The agent can omit solve_origin, so the primitive's semantic class must
        # independently activate the sanctioned-observation requirement.
        fake = self._symbolic_fixture(tagged=False, primitive_class="solution-reconstruction")
        result = self._run_symbolic_gate(fake)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_rev_route_assessment_without_tag_or_symbolic_class_is_denied(self):
        note = {
            "kind": "route-assessment",
            "leads": ["checker"],
            "dimensions": {"program_shapes": ["checker"], "vulnerability_surfaces": []},
        }
        fake = self._symbolic_fixture(tagged=False, primitive_class="control-flow", notes=[note])
        result = self._run_symbolic_gate(fake)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_later_pwn_note_cannot_erase_prior_rev_route(self):
        old_rev_note = {
            "kind": "route-assessment", "leads": ["checker"],
            "dimensions": {"program_shapes": ["checker"], "vulnerability_surfaces": []},
        }
        current_pwn_note = {
            "kind": "route-assessment",
            "leads": ["checker", "stack-overwrite"],
            "dimensions": {
                "program_shapes": ["checker"],
                "vulnerability_surfaces": ["stack-overwrite-candidate"],
            },
        }
        fake = self._symbolic_fixture(
            tagged=False, primitive_class="control-flow", notes=[old_rev_note, current_pwn_note])
        result = self._run_symbolic_gate(fake)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_mixed_route_without_tag_or_symbolic_class_keeps_documented_residual(self):
        note = {
            "kind": "route-assessment",
            "leads": ["checker", "stack-overwrite"],
            "dimensions": {
                "program_shapes": ["checker"],
                "vulnerability_surfaces": ["stack-overwrite-candidate"],
            },
        }
        fake = self._symbolic_fixture(
            tagged=False, primitive_class="control-flow", notes=[note])
        result = self._run_symbolic_gate(fake)
        self.assertTrue(result["verified"])

    def test_direct_pwn_measurement_overrides_provisional_rev_route(self):
        note = {
            "kind": "route-assessment", "leads": ["checker"],
            "dimensions": {"program_shapes": ["checker"], "vulnerability_surfaces": []},
        }
        fake = self._symbolic_fixture(tagged=False, primitive_class="control-flow", notes=[note])
        fake._primitives["prim_1"]["self_evidence"] = ["obs_pwn_control"]
        fake._observations["obs_pwn_control"] = {
            "kind": "pwn.reg", "quality": {"level": "direct"},
            "validity": {"state": "active"},
        }
        result = self._run_symbolic_gate(fake)
        self.assertTrue(result["verified"])
        self.assertNotIn("advisory", result)

    def test_inactive_or_nondirect_pwn_does_not_override_rev_route(self):
        note = {
            "kind": "route-assessment", "leads": ["checker"],
            "dimensions": {"program_shapes": ["checker"]},
        }
        for quality, validity in (("direct", "invalidated"), ("heuristic", "active")):
            with self.subTest(quality=quality, validity=validity):
                fake = self._symbolic_fixture(
                    tagged=False, primitive_class="control-flow", notes=[note])
                fake._primitives["prim_1"]["self_evidence"] = ["obs_pwn"]
                fake._observations["obs_pwn"] = {
                    "kind": "pwn.reg", "quality": {"level": quality},
                    "validity": {"state": validity},
                }
                result = self._run_symbolic_gate(fake)
                self.assertFalse(result["verified"])
                self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_direct_pwn_measurement_does_not_erase_symbolic_primitive_class(self):
        note = {
            "kind": "route-assessment", "leads": ["checker"],
            "dimensions": {"program_shapes": ["checker"], "vulnerability_surfaces": []},
        }
        fake = self._symbolic_fixture(
            tagged=False, primitive_class="solution-reconstruction", notes=[note])
        fake._primitives["prim_1"]["self_evidence"] = ["obs_pwn_control"]
        fake._observations["obs_pwn_control"] = {
            "kind": "pwn.reg", "quality": {"level": "direct"},
            "validity": {"state": "active"},
        }
        result = self._run_symbolic_gate(fake)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_rev_symbolic_primitive_engine_spoof_is_denied_without_observation(self):
        # Primitive producer metadata is agent-authored and cannot substitute for
        # the corresponding active symsolve observation.
        result = self._run_symbolic_gate(self._symbolic_fixture(engine="symsolve"))
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_environment_cannot_relax_symbolic_engine_gate(self):
        with patch.dict(os.environ, {"RAT_ENGINE_GATE": "advisory"}):
            result = self._run_symbolic_gate(self._symbolic_fixture())
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")

    def test_rev_symbolic_gate_accepts_operator_attestation(self):
        attestation = {
            "schema": "rat.writeup-attestation/v1", "operator": "operator",
            "confirmed_at": "2026-09-24T12:00:00+00:00",
            "result": "manual solve reviewed", "evidence": [self.record["report_digest"]],
        }
        result = self._run_symbolic_gate(self._symbolic_fixture(attestation=attestation))
        self.assertTrue(result["verified"])
        self.assertTrue(result["operator_attested"])

    def test_attestation_cannot_use_invalidated_observation_evidence(self):
        digest = "sha256:" + "f" * 64
        attestation = {
            "schema": "rat.writeup-attestation/v1", "operator": "operator",
            "confirmed_at": "2026-09-24T12:00:00+00:00",
            "result": "manual solve reviewed", "evidence": [digest],
        }
        fake = self._symbolic_fixture(attestation=attestation)
        fake._primitives["prim_1"]["self_evidence"] = ["obs_old"]
        fake._observations["obs_old"] = {
            "validity": {"state": "invalidated"}, "evidence": [digest],
        }
        result = self._run_symbolic_gate(fake)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "unsanctioned-symbolic-engine")


class RatbenchIsolationTests(unittest.TestCase):
    def test_mode_b_workspace_excludes_ground_truth(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as sandbox:
            for name, data in (("CLAUDE.md", "runtime instructions\n"),
                               ("AGENTS.md", "runtime instructions\n"),
                               ("FLAG_FORMAT", "FLAG{...}\n")):
                with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                    fh.write(data)
            os.makedirs(os.path.join(root, "bin"))
            with open(os.path.join(root, "bin", "rat"), "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\n")
            os.makedirs(os.path.join(root, "solve", "_template"))
            with open(os.path.join(root, "solve", "_template", "README"), "w", encoding="utf-8") as fh:
                fh.write("template\n")
            fixture = os.path.join(root, "bench", "artifacts", "case")
            os.makedirs(fixture)
            with open(os.path.join(fixture, "src.c"), "w", encoding="utf-8") as fh:
                fh.write('const char *answer = "open-sesame";\n')
            with open(os.path.join(fixture, "route.json"), "w", encoding="utf-8") as fh:
                fh.write('{"expected":"answer"}\n')
            with open(os.path.join(fixture, "chall"), "wb") as fh:
                fh.write(b"runtime-binary")

            entry = {
                "id": "case", "dir": "bench/artifacts/case", "binary": "chall",
                "source": "src.c", "route_fixture": "route.json",
            }
            original = ratbench.ctf_home
            ratbench.ctf_home = lambda: root
            try:
                kit_root, chal_dir, binary = ratbench._prepare_eval_workspace(entry, sandbox)
            finally:
                ratbench.ctf_home = original

            self.assertTrue(os.path.isfile(os.path.join(kit_root, "CLAUDE.md")))
            self.assertTrue(os.path.isfile(os.path.join(kit_root, "AGENTS.md")))
            self.assertTrue(os.path.isfile(binary))
            self.assertFalse(os.path.exists(os.path.join(kit_root, "bench")))
            self.assertFalse(os.path.exists(os.path.join(chal_dir, "src.c")))
            self.assertFalse(os.path.exists(os.path.join(chal_dir, "route.json")))

    def test_mode_b_rejects_normalized_ground_truth_aliases(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as sandbox:
            fixture = os.path.join(root, "bench", "artifacts", "case")
            os.makedirs(os.path.join(root, "bin"))
            os.makedirs(fixture)
            for name in ("src.c", "route.json", "chall"):
                with open(os.path.join(fixture, name), "wb") as fh:
                    fh.write(b"fixture")
            entry = {
                "id": "case", "dir": "bench/artifacts/case", "binary": "chall",
                "source": "src.c", "route_fixture": "route.json",
                "runtime_files": ["sub/../src.c"],
            }
            original = ratbench.ctf_home
            ratbench.ctf_home = lambda: root
            try:
                with self.assertRaises(ValueError):
                    ratbench._prepare_eval_workspace(entry, sandbox)
            finally:
                ratbench.ctf_home = original

    def test_mode_b_rejects_symlink_ground_truth_aliases(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as sandbox:
            fixture = os.path.join(root, "bench", "artifacts", "case")
            os.makedirs(fixture)
            for name in ("src.c", "route.json", "chall"):
                with open(os.path.join(fixture, name), "wb") as fh:
                    fh.write(b"fixture")
            os.symlink("src.c", os.path.join(fixture, "source-alias"))
            entry = {
                "id": "case", "dir": "bench/artifacts/case", "binary": "chall",
                "source": "src.c", "route_fixture": "route.json",
                "runtime_files": ["source-alias"],
            }
            with patch.object(ratbench, "ctf_home", return_value=root):
                with self.assertRaisesRegex(ValueError, "ground-truth/state file"):
                    ratbench._prepare_eval_workspace(entry, sandbox)

    def test_mode_b_rejects_symlink_flag_alias(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as sandbox:
            fixture = os.path.join(root, "bench", "artifacts", "case")
            os.makedirs(fixture)
            for name in ("chall", "flag.txt"):
                with open(os.path.join(fixture, name), "wb") as target:
                    target.write(b"CTF{secret}")
            os.symlink("flag.txt", os.path.join(fixture, "data.bin"))
            entry = {"id": "case", "dir": "bench/artifacts/case", "binary": "chall",
                     "runtime_files": ["data.bin"]}
            with patch.object(ratbench, "ctf_home", return_value=root):
                with self.assertRaisesRegex(ValueError, "flag file"):
                    ratbench._prepare_eval_workspace(entry, sandbox)
            self.assertFalse(os.path.exists(os.path.join(sandbox, "ctf-rat", "solve", "case", "data.bin")))

    def test_mode_b_rejects_symlink_alias_to_state_directory(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as sandbox:
            fixture = os.path.join(root, "bench", "artifacts", "case")
            state_dir = os.path.join(fixture, ".rat")
            os.makedirs(state_dir)
            with open(os.path.join(fixture, "chall"), "wb") as fh:
                fh.write(b"binary")
            with open(os.path.join(state_dir, "STATE.jsonl"), "w", encoding="utf-8") as fh:
                fh.write("private state")
            os.symlink(".rat", os.path.join(fixture, "state-alias"))
            entry = {
                "id": "case", "dir": "bench/artifacts/case", "binary": "chall",
                "runtime_files": ["state-alias/STATE.jsonl"],
            }
            with patch.object(ratbench, "ctf_home", return_value=root):
                with self.assertRaisesRegex(ValueError, "ground-truth/state file"):
                    ratbench._prepare_eval_workspace(entry, sandbox)

    def test_mode_b_runtime_export_rejects_symlink_to_benchmark_tree(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as sandbox:
            bench = os.path.join(root, "bench")
            runtime_bin = os.path.join(root, "bin")
            os.makedirs(bench)
            os.makedirs(runtime_bin)
            with open(os.path.join(bench, "answer"), "w", encoding="utf-8") as fh:
                fh.write("secret")
            os.symlink(os.path.join(bench, "answer"), os.path.join(runtime_bin, "answer-alias"))
            with patch.object(ratbench, "ctf_home", return_value=root):
                with self.assertRaisesRegex(ValueError, "symlink escapes allowlist"):
                    ratbench._copy_runtime_export(os.path.join(sandbox, "export"))

    def test_mode_b_rejects_fixture_directory_symlink_escape(self):
        ratbench = load_ratbench()
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(root, "fixture-alias"))
            entry = {"id": "case", "dir": "fixture-alias", "binary": "chall"}
            with patch.object(ratbench, "ctf_home", return_value=root):
                with self.assertRaisesRegex(ValueError, "escapes CTF_HOME"):
                    ratbench._prepare_eval_workspace(entry, os.path.join(root, "sandbox"))


if __name__ == "__main__":
    unittest.main()
