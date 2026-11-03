"""Native ELF regression for the concrete verifier's exit and output contract."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ANGR_PYTHON = ROOT / ".venv-angr/bin/python"
HARNESS = ROOT / "solve/_template/rev/symsolve.py"


@unittest.skipUnless(ANGR_PYTHON.is_file() and shutil.which("gcc"),
                     "native angr interpreter and gcc required")
class SymsolveExitE2E(unittest.TestCase):
    def test_native_cli_exit_overflow_and_timeout(self):
        cases = (
            ("exit0", "return 0;", [], True, 0),
            ("exit7", "return 7;", [], False, 7),
            ("expected7", "return 7;", ["--expect-exit-code", "7"], True, 7),
            ("signal", "raise(SIGTERM); return 0;", [], False, -15),
            ("overflow", "for (int i=0;i<1048580;i++) putchar('A'); return 0;",
             [], False, None),
            ("timeout", "sleep(30); return 0;", [], False, None),
        )
        with tempfile.TemporaryDirectory(prefix="symsolve-exit-e2e-") as folder:
            root = Path(folder)
            for name, ending, extra, should_pass, expected_rc in cases:
                with self.subTest(name=name):
                    source, binary, result = (root / (name + suffix)
                                              for suffix in (".c", ".bin", ".json"))
                    source.write_text(
                        "#include <stdio.h>\n#include <signal.h>\n#include <unistd.h>\n"
                        "int main(void){ char c=0; read(0,&c,1); if(c!='A') return 2;"
                        "puts(\"REVIEW_OK\"); fflush(stdout); " + ending + "}\n")
                    subprocess.run(["gcc", "-O0", "-no-pie", "-o", str(binary), str(source)],
                                   check=True, capture_output=True, timeout=30)
                    run = subprocess.run(
                        [str(ANGR_PYTHON), str(HARNESS), str(binary),
                         "--find-str", "REVIEW_OK", "--stdin", "1", "--printable",
                         "--timeout", "20", "--result", str(result), *extra],
                        capture_output=True, text=True, timeout=50)
                    self.assertTrue(result.exists(), run.stderr)
                    doc = json.loads(result.read_text())
                    self.assertTrue(doc["found"], run.stderr)
                    self.assertEqual(doc["verified"], should_pass)
                    self.assertEqual(doc["concrete_verify"] == "pass", should_pass)
                    self.assertEqual(run.returncode == 0, should_pass)
                    if expected_rc is not None:
                        self.assertEqual(doc["target_returncode"], expected_rc)
                    self.assertEqual(doc["expected_exit_code"], 7 if extra else 0)


if __name__ == "__main__":
    unittest.main()
