import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin" / "pwnscope"


def manifest(mode="none", allowlist=None):
    return {
        "schema": "rat.run/v1",
        "target_policy": {
            "guard_challenge": "fixture",
            "network_mode": mode,
            "allowlist": allowlist or [],
        },
    }


class PwnscopeTests(unittest.TestCase):
    def run_case(self, script, run_manifest=None):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            solve = root / "solve.py"
            solve.write_text(script, encoding="utf-8")
            if run_manifest is not None:
                (root / "run.json").write_text(json.dumps(run_manifest), encoding="utf-8")
            result = subprocess.run(
                [str(TOOL), str(solve), "--json"],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            return result, json.loads(result.stdout)

    def test_local_only_passes_without_manifest(self):
        result, report = self.run_case("from pwn import *\nio = process('./fixture')\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["summary"]["verdict"], "pass")
        self.assertEqual(report["summary"]["network_calls"], 0)

    def test_network_requires_manifest(self):
        result, report = self.run_case("from pwn import *\nio = remote('ctf.test', 31337)\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn("network-without-manifest", {item["code"] for item in report["findings"]})

    def test_exact_single_target_passes(self):
        result, report = self.run_case(
            "from pwn import *\nio = process('./fixture') if args.LOCAL else remote('ctf.test', 31337)\n",
            manifest("ctfguard-target", ["ctf.test:31337"]),
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["manifest_target"], "ctf.test:31337")
        self.assertEqual(report["summary"]["errors"], 0)

    def test_target_mismatch_fails(self):
        result, report = self.run_case(
            "from pwn import *\nio = remote('other.test', 4444)\n",
            manifest("ctfguard-target", ["ctf.test:31337"]),
        )
        self.assertEqual(result.returncode, 2)
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("host-mismatch", codes)
        self.assertIn("port-mismatch", codes)

    def test_network_loop_fails(self):
        result, report = self.run_case(
            "from pwn import *\nfor _ in range(10):\n    io = remote('ctf.test', 31337)\n",
            manifest("ctfguard-target", ["ctf.test:31337"]),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("network-call-in-loop", {item["code"] for item in report["findings"]})

    def test_aliased_network_call_requires_manifest(self):
        result, report = self.run_case("from pwn import remote as dial\nio = dial('ctf.test', 31337)\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn("network-without-manifest", {item["code"] for item in report["findings"]})

    def test_manifest_rejects_out_of_range_port(self):
        result, report = self.run_case(
            "from pwn import *\nio = remote('ctf.test', 99999)\n",
            manifest("ctfguard-target", ["ctf.test:99999"]),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("single-target", {item["code"] for item in report["findings"]})


if __name__ == "__main__":
    unittest.main()
