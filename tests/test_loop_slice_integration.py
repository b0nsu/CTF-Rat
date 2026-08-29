import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))

try:
    import angr  # noqa: F401
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False


@unittest.skipUnless(shutil.which("gcc") and HAVE_ANGR, "gcc+angr required for loop-slice integration")
class LoopSliceIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = pathlib.Path(self.tmp.name)
        self.src = self.work / "loop.c"
        self.exe = self.work / "loop"
        self.store = self.work / "store"
        self.src.write_text(
            "#include <stdint.h>\n"
            "__attribute__((noinline)) int loop_accum(volatile int n, int x) {\n"
            "  volatile int i = 0;\n"
            "  while (i < n) { x += 8; i++; }\n"
            "  return x;\n"
            "}\n"
            "int main(void) { return loop_accum(3, 1) == 25 ? 0 : 1; }\n"
        )
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", str(self.src), "-o", str(self.exe)], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _run_json(self, argv):
        p = subprocess.run(argv, text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def _symbol(self, name):
        out = subprocess.run(["nm", str(self.exe)], text=True, capture_output=True, check=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] == name:
                return "0x" + parts[0]
        self.fail("symbol not found: %s" % name)

    def test_data_slice_emits_loop_summary_artifact_and_projection(self):
        profile = self._run_json([
            str(BIN / "rat-profile"), str(self.exe), "--store", str(self.store), "--format", "json"
        ])
        pd = profile["artifacts"][0]["digest"]
        doc = self._run_json([
            str(BIN / "rat-slice"), str(self.exe), "--store", str(self.store), "--format", "json",
            "--profile", pd, "--mode", "data", "--backward", self._symbol("loop_accum"), "--source", "stdin",
        ])
        self.assertEqual(doc["summary"]["claim"], "dependency-candidate")
        loop_analysis = doc["summary"]["within_function"]["loop_analysis"]
        self.assertEqual(loop_analysis["schema"], "rat.loop-summary/v1")
        self.assertGreaterEqual(loop_analysis["coverage"]["loop_count"], 1)
        self.assertTrue(any(a["kind"] == "loop-summary" for a in doc["artifacts"]))
        self.assertFalse(doc["extensions"]["analysis_policy"]["promotion_allowed"])
        for loop in loop_analysis["loops"]:
            self.assertFalse(loop["eligible_for_fast_forward"])
            for recurrence in loop["recurrences"]:
                self.assertEqual(recurrence["quality"], "candidate")


if __name__ == "__main__":
    unittest.main()
