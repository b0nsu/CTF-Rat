"""Exercise child stderr topology without altering the default runner contract."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib import analysis
from ratlib.runner import run

PROGRAM = "import sys; sys.stdout.write('OUT\\n'); sys.stderr.write('ERR\\n')"


class StdioTopologyTests(unittest.TestCase):
    def tool(self, mode):
        return run([sys.executable, "-c", PROGRAM],
                   input_bytes=b"", timeout_seconds=5,
                   stderr_mode=mode)

    def test_default_separate_pipes(self):
        default = run([sys.executable, "-c", PROGRAM],
                      input_bytes=b"", timeout_seconds=5)
        self.assertEqual(default.exit_code, 0)
        self.assertEqual(default.stdout.preview, b"OUT\n")
        self.assertEqual(default.stderr.preview, b"ERR\n")
        self.assertEqual(self.tool("pipe").stderr.preview, default.stderr.preview)

    def test_devnull_and_merged_stdout(self):
        devnull = self.tool("devnull")
        self.assertEqual(devnull.exit_code, 0)
        self.assertEqual(devnull.stdout.preview, b"OUT\n")
        self.assertEqual(devnull.stderr.preview, b"")
        merged = self.tool("stdout")
        self.assertEqual(merged.exit_code, 0)
        self.assertIn(b"OUT\n", merged.stdout.preview)
        self.assertIn(b"ERR\n", merged.stdout.preview)
        self.assertEqual(merged.stderr.preview, b"")

    def test_reject_unsupported_mode_before_spawning(self):
        with self.assertRaisesRegex(ValueError, "stderr_mode"):
            self.tool("inherit")

    def test_nondefault_topology_cannot_reuse_default_verify_identity(self):
        profile = {"environment": {"libc": "sha256:example"}}
        scenario = {"argv": [], "cwd": None, "env": {}}
        default = analysis.execution_environment(profile, scenario)
        self.assertEqual(default, analysis.execution_environment(profile, scenario, "pipe"))
        self.assertNotEqual(default, analysis.execution_environment(profile, scenario, "devnull"))
        self.assertNotEqual(default, analysis.execution_environment(profile, scenario, "stdout"))


if __name__ == "__main__":
    unittest.main()
