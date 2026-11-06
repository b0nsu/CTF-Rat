"""End-to-end checks for the large-input guard through the public front doors."""
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest


BIN = pathlib.Path(__file__).resolve().parents[1] / "bin"


class LargeInputGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.binary = pathlib.Path(self.temporary.name) / "large-true"
        shutil.copyfile(shutil.which("true"), self.binary)
        with self.binary.open("ab") as out:
            out.truncate(3 * 1024 * 1024)

    def run_tool(self, *args):
        return subprocess.run([str(BIN / args[0]), *map(str, args[1:])],
                              capture_output=True, text=True, timeout=20)

    def test_route_preserves_actionable_size_diagnostic(self):
        result = self.run_tool("rat", "route", self.binary, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads(result.stdout)
        diagnostics = doc["diagnostics"]
        self.assertTrue(any("--max-input-mb" in item.get("message", "") for item in diagnostics))
        self.assertTrue(any(item.get("code") == "analysis_unavailable" for item in diagnostics))
        self.assertTrue(any("--func-size" in item for item in doc["unresolved"]))

    def test_slice_frontdoor_reports_size_refusal(self):
        result = self.run_tool("rat", "query", "slice", self.binary,
                               "--backward", "0x0", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["coverage"]["producer_coverage"], "refused")
        self.assertEqual(doc["diagnostics"][0]["code"], "analysis_unavailable")

    def test_nonfinite_limit_is_a_usage_error(self):
        result = self.run_tool("revq", self.binary, "--max-input-mb", "nan")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
