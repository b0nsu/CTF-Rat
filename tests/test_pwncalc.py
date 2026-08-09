import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin" / "pwncalc"


class PwncalcTests(unittest.TestCase):
    def run_tool(self, *args, check=True):
        result = subprocess.run(
            [str(TOOL), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if check and result.returncode != 0:
            self.fail(result.stderr or result.stdout)
        return result

    def test_base_and_resolve(self):
        base = self.run_tool("--json", "base", "--leak", "0x7f0012345000", "--offset", "0x12345000")
        base_doc = json.loads(base.stdout)
        self.assertEqual(base_doc["result"]["base"], 0x7F0000000000)
        self.assertTrue(base_doc["checks"]["alignment"])

        resolved = self.run_tool("--json", "resolve", "--base", "0x400000", "--offset", "0x1234")
        self.assertEqual(json.loads(resolved.stdout)["result"]["address"], 0x401234)

    def test_alignment_failure_is_nonzero(self):
        result = self.run_tool("base", "--leak", "0x2001", "--offset", "0x1000", check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("alignment", result.stderr)

    def test_negative_string_occurrence_is_rejected(self):
        result = self.run_tool(
            "elf-offset", "--elf", "/bin/true", "--string", "ELF", "--occurrence", "-1", check=False
        )
        self.assertNotEqual(result.returncode, 0)

    def test_elf_offsets_and_relocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "fixture.c"
            library = root / "fixture.so"
            source.write_text(
                'const char marker[] = "PWN_CALC_MARKER";\n'
                'int leaked_symbol(void) { return 7; }\n'
                'int wanted_symbol(void) { return marker[0]; }\n',
                encoding="ascii",
            )
            compiled = subprocess.run(
                ["gcc", "-shared", "-fPIC", "-Wl,--build-id=none", "-o", str(library), str(source)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)

            leak_offset_doc = json.loads(self.run_tool(
                "--json", "elf-offset", "--elf", str(library), "--symbol", "leaked_symbol"
            ).stdout)
            leak_offset = leak_offset_doc["result"]["offset"]
            self.assertTrue(leak_offset_doc["artifact"]["sha256"].startswith("sha256:"))

            string_doc = json.loads(self.run_tool(
                "--json", "elf-offset", "--elf", str(library), "--string", "PWN_CALC_MARKER"
            ).stdout)
            self.assertTrue(string_doc["checks"]["inside_load_image"])

            runtime_base = 0x7F1000000000
            relocated = json.loads(self.run_tool(
                "--json", "relocate", "--elf", str(library),
                "--leak", hex(runtime_base + leak_offset), "--leak-symbol", "leaked_symbol",
                "--symbol", "wanted_symbol", "--string", "PWN_CALC_MARKER",
            ).stdout)
            self.assertEqual(relocated["result"]["base"], runtime_base)
            self.assertEqual(
                relocated["result"]["addresses"]["wanted_symbol"],
                runtime_base + relocated["result"]["offsets"]["wanted_symbol"],
            )
            self.assertTrue(relocated["checks"]["targets_inside_load_image"])


if __name__ == "__main__":
    unittest.main()
