import base64
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
__import__("sys").path.insert(0, str(BIN))
from ratlib.schema import validate as validate_contract


class DoctorTests(unittest.TestCase):
    def test_reports_artifact_routes_without_running_regression(self):
        result = subprocess.run([str(BIN / "rat-doctor"), "/bin/true", "--format", "json"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads(result.stdout)
        validate_contract(doc, "rat.tool-result/v1")
        self.assertEqual(doc["schema"], "rat.tool-result/v1")
        report = doc["summary"]
        self.assertEqual(report["binary"]["format"], "ELF")
        self.assertTrue(report["binary"]["digest"].startswith("sha256:"))
        self.assertIn(report["routes"]["native"]["status"], ("available", "unavailable"))
        self.assertFalse(report["regression"]["checked"])

    def test_missing_binary_is_input_error(self):
        result = subprocess.run([str(BIN / "rat-doctor"), "/definitely/missing"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 4)


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.work = pathlib.Path(self.temp.name)

    def tearDown(self): self.temp.cleanup()

    def command(self, *args):
        return subprocess.run([str(BIN / "rat-scenario"), *map(str, args)], text=True, capture_output=True)

    def test_binary_stdin_roundtrip_and_stable_digest(self):
        payload = self.work / "input.bin"; payload.write_bytes(b"A\x00\xff\n")
        scenario = self.work / "scenario.json"
        made = self.command("init", "--name", "binary", "--stdin-file", payload, "--output", scenario)
        self.assertEqual(made.returncode, 0, made.stderr)
        doc = json.loads(scenario.read_text())
        self.assertEqual(base64.b64decode(doc["stdin_base64"]), payload.read_bytes())
        first = self.command("validate", scenario); second = self.command("validate", scenario)
        self.assertEqual(first.returncode, 0, first.stderr); self.assertEqual(first.stdout, second.stdout)

    def test_binary_stdin_is_consumed_by_dynamic_runner(self):
        payload = self.work / "input.bin"; payload.write_bytes(b"A\x00\xff\n")
        scenario = self.work / "scenario.json"; store = self.work / "store"
        self.assertEqual(self.command("init", "--name", "cat", "--stdin-file", payload, "--output", scenario).returncode, 0)
        profile = subprocess.run([str(BIN / "rat-profile"), "/bin/cat", "--store", str(store), "--format", "json"], text=True, capture_output=True)
        self.assertEqual(profile.returncode, 0, profile.stderr)
        profile_digest = json.loads(profile.stdout)["artifacts"][0]["digest"]
        dynamic = subprocess.run([str(BIN / "rat-dyn"), "/bin/cat", "--store", str(store), "--format", "json", "--profile", profile_digest, "--scenario", str(scenario)], text=True, capture_output=True)
        self.assertEqual(dynamic.returncode, 0, dynamic.stderr)
        stdout_digest = json.loads(dynamic.stdout)["artifacts"][1]["digest"]
        from ratlib.artifact import get
        self.assertEqual(get(stdout_digest, root=str(store)), payload.read_bytes())

    def test_rejects_ambiguous_stdin_and_cwd_escape(self):
        scenario = self.work / "bad.json"
        scenario.write_text(json.dumps({"schema": "rat.scenario/v1", "stdin": "x", "stdin_base64": "eA=="}))
        self.assertEqual(self.command("validate", scenario).returncode, 4)
        scenario.write_text(json.dumps({"schema": "rat.scenario/v1", "cwd": "../escape"}))
        self.assertEqual(self.command("validate", scenario).returncode, 4)


if __name__ == "__main__": unittest.main()
