import importlib.machinery
import importlib.util
import os
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
    def __init__(self, events, primitives):
        self._events = events
        self._primitives = primitives

    def read(self):
        return list(self._events)

    def view(self):
        return {"primitives": dict(self._primitives)}


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


if __name__ == "__main__":
    unittest.main()
