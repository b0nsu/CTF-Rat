"""Front-door coverage for `rat query pwn`.

The contract/usage cases are dependency-free.  The real-ELF smoke test runs
only in the Linux toolchain environment used by the repository's full tests.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))

from ratlib.schema import validate


def run_rat(*args, timeout=60):
    proc = subprocess.run(
        [str(BIN / "rat"), *map(str, args)],
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


class PwnQueryContract(unittest.TestCase):
    def test_query_help_lists_pwn_card(self):
        code, out, err = run_rat("query", "--help")
        self.assertEqual(code, 0, err)
        self.assertIn("pwn", out)

    def test_missing_binary_is_schema_valid_input_error(self):
        code, out, err = run_rat("query", "pwn", "/definitely/missing", "--format", "json")
        self.assertEqual(code, 4, err)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")
        self.assertEqual(doc["query"], "pwn")
        self.assertEqual(doc["status"], "error")
        self.assertEqual(doc["diagnostics"][0]["code"], "input_invalid")


@unittest.skipUnless(
    sys.platform.startswith("linux") and shutil.which("gcc") and shutil.which("readelf"),
    "needs Linux + gcc + readelf",
)
class PwnQueryRealElf(unittest.TestCase):
    def test_profile_projection_keeps_facts_separate_from_route_heuristics(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            src = work / "pwn.c"
            exe = work / "pwn"
            store = work / "store"
            src.write_text(
                "#include <stdio.h>\n"
                "#include <unistd.h>\n"
                "int main(void){char b[8]; read(0,b,64); printf(b); return 0;}\n"
            )
            subprocess.run(
                ["gcc", "-O0", "-fno-pie", "-no-pie", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            code, out, err = run_rat(
                "query", "pwn", str(exe), "--store", str(store), "--format", "json"
            )
            self.assertEqual(code, 0, err)
            doc = json.loads(out)
            validate(doc, "rat.query-result/v1")
            self.assertIn(doc["status"], ("ok", "partial"))
            self.assertIn("read", doc["facts"]["sinks"]["overflow_bounded"])
            self.assertIn("printf", doc["facts"]["sinks"]["format"])
            self.assertIn("candidate_routes", doc["heuristics"])
            self.assertNotIn("verified_primitive", doc["facts"])
            self.assertEqual(doc["facts"]["sink_counts"]["format"], 1)


if __name__ == "__main__":
    unittest.main()
