import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ratlib.decomp_cache import write_meta


ROOT = Path(__file__).resolve().parents[1]
DECOMP = ROOT / "bin" / "decomp"
LOOKUP = ROOT / "bin" / "ratlib" / "decomp_lookup.py"
PE_HEADER = b"MZ" + b"\0" * 58 + b"\x40\0\0\0" + b"PE\0\0"


@unittest.skipUnless(shutil.which("timeout") or shutil.which("gtimeout"), "decomp needs timeout")
class DecompAddressLookupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.ghidra = root / "ghidra"
        (self.ghidra / "support").mkdir(parents=True)
        (self.ghidra / "Ghidra").mkdir()
        (self.ghidra / "Ghidra" / "application.properties").write_text("application.version=fake\n")
        self.calls = root / "calls"
        analyzer = self.ghidra / "support" / "analyzeHeadless"
        analyzer.write_text("""#!/usr/bin/env bash
set -euo pipefail
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [ "${args[$i]}" = "DecompOne.java" ]; then
    cache="${args[$((i+1))]}"
    addr="${args[$((i+2))]}"
    printf '%s\\n' "$addr" >> "$DECOMP_TEST_CALLS"
    printf 'int FUN_%s(void) { return 7; }\\n' "$addr" > "$cache/FUN_$addr.c"
    printf '%s\\tFUN_%s\\t8\\n' "$addr" "$addr" >> "$cache/_index.txt"
    exit 0
  fi
done
exit 66
""")
        analyzer.chmod(0o755)
        self.env = dict(os.environ, CTF_HOME=str(ROOT), GHIDRA_HOME=str(self.ghidra),
                        DECOMP_TEST_CALLS=str(self.calls))

    def fixture(self, name, binary_header, address, image_base=None):
        binary = Path(self.temp.name) / name
        binary.write_bytes(binary_header)
        cache = Path(str(binary) + ".decomp")
        cache.mkdir()
        exported = f"{address:08x}_FUN_{address:08x}"
        (cache / "_index.txt").write_text(f"{address:08x}\tFUN_{address:08x}\t8\t{exported}\n")
        (cache / f"{exported}.c").write_text(f"int FUN_{address:08x}(void) {{ return 3; }}\n")
        if image_base is not None:
            (cache / ".rat-decomp-status.json").write_text(json.dumps({
                "image_base": format(image_base, "x"), "discovered": 1,
                "exported": 1, "failed": [],
            }))
        write_meta(str(cache), str(binary), str(self.ghidra), str(ROOT / "bin" / "ghidra_scripts"), "complete")
        return binary

    def run_decomp(self, binary, request):
        return subprocess.run([str(DECOMP), str(binary), request], env=self.env,
                              capture_output=True, text=True, timeout=20)

    def lookup(self, binary, request):
        output = subprocess.check_output([sys.executable, str(LOOKUP), str(binary),
                                          str(binary) + ".decomp", request], text=True)
        return output.strip().split("\t")

    def test_exported_cache_aliases_do_not_launch_one_shot(self):
        nonpie = self.fixture("nonpie", b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x02\0", 0x401348, 0x400000)
        pie = self.fixture("pie", b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x03\0", 0x101348, 0x100000)
        pe = self.fixture("pe.exe", PE_HEADER, 0x140001070, 0x140000000)
        cases = [
            (nonpie, ["0x401348", "sub_401348", "FUN_00401348"]),
            (pie, ["0x401348", "sub_401348", "0x1348", "FUN_00101348"]),
            (pe, ["0x140001070", "sub_140001070", "FUN_140001070"]),
        ]
        for binary, requests in cases:
            for request in requests:
                with self.subTest(binary=binary.name, request=request):
                    result = self.run_decomp(binary, request)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("return 3", result.stdout)
                    self.assertNotIn("one-shot", result.stderr)
        self.assertFalse(self.calls.exists())

    def test_one_shot_uses_format_and_observed_base(self):
        nonpie = self.fixture("nonpie", b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x02\0", 0x401348, 0x400000)
        pie = self.fixture("pie", b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x03\0", 0x101348, 0x100000)
        pe = self.fixture("pe.exe", PE_HEADER, 0x140001070, 0x140000000)
        self.assertEqual(self.lookup(nonpie, "sub_401360")[2:], ["401360", "401360"])
        self.assertEqual(self.lookup(pie, "sub_401360")[2:], ["101360", "1360"])
        self.assertEqual(self.lookup(pe, "sub_140001080")[2:], ["140001080", "140001080"])
        for binary, request in [(nonpie, "sub_401360"), (pie, "sub_401360"),
                                (pe, "sub_140001080")]:
            with self.subTest(binary=binary.name):
                result = self.run_decomp(binary, request)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("return 7", result.stdout)
        self.assertEqual(self.calls.read_text().splitlines(), ["401360", "101360", "140001080"])

    def test_pie_without_recorded_base_does_not_guess(self):
        pie = self.fixture("pie", b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x03\0", 0x101348)
        self.assertEqual(self.lookup(pie, "sub_401348"), ["unknown", "-", "-", "-"])
        result = self.run_decomp(pie, "sub_401348")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
