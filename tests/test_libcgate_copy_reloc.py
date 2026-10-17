"""Regression for libcgate COPY relocations from a digest-bound run manifest."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIBCGATE = Path(os.environ.get("CTF_RAT_LIBCGATE", str(ROOT / "bin" / "libcgate")))
CC = shutil.which("cc")
READELF = shutil.which("readelf")


@unittest.skipUnless(CC and READELF, "requires a C compiler and readelf")
class LibcgateCopyRelocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "sample.c"
        self.binary = self.root / "chall"

    def compile(self, source):
        self.source.write_text(source, encoding="utf-8")
        subprocess.run([CC, "-O0", "-fno-pie", "-no-pie", "-o", str(self.binary),
                        str(self.source)], check=True, capture_output=True, timeout=15)
        self.manifest()

    def manifest(self, binary_name="chall", digest=None):
        if digest is None:
            digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        (self.root / "run.json").write_text(json.dumps({
            "scaffold": {"binary": binary_name},
            "inputs": [{"role": "binary", "name": binary_name, "sha256": digest,
                        "size": self.binary.stat().st_size}],
        }), encoding="utf-8")

    def audit(self):
        return subprocess.run([sys.executable, str(LIBCGATE), str(self.root)],
                              text=True, capture_output=True, timeout=15)

    def test_copy_relocation_prints_executable_address(self):
        self.compile('#include <stdio.h>\nextern FILE *stdout;\nint main(void){return fprintf(stdout,"ok\\n") < 0;}\n')
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COPY relocations (executable-owned globals", result.stdout)
        original = subprocess.check_output([READELF, "-rW", str(self.binary)], text=True)
        match = re.search(r"^([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+R_X86_64_COPY\s+[^\n]*\sstdout@", original, re.M)
        self.assertIsNotNone(match, original)
        self.assertIn("stdout @ 0x%x [R_X86_64_COPY]" % int(match.group(1), 16), result.stdout)

    def test_non_copy_elf_does_not_claim_a_copy(self):
        self.compile('#include <stdio.h>\nint main(void){return puts("ok") < 0;}\n')
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COPY relocations: none detected", result.stdout)
        self.assertNotIn("executable-owned globals", result.stdout)

    def test_changed_binary_digest_blocks_stale_copy_fact(self):
        self.compile('#include <stdio.h>\nextern FILE *stdout;\nint main(void){return fprintf(stdout,"ok\\n") < 0;}\n')
        self.manifest(digest="0" * 64)
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing stale COPY facts", result.stdout)
        self.assertNotIn("stdout @", result.stdout)

    def test_manifest_path_traversal_is_rejected(self):
        self.compile('#include <stdio.h>\nint main(void){return puts("ok") < 0;}\n')
        self.manifest(binary_name="../chall")
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn("safe challenge-local scaffold binary", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)

    def test_non_elf_is_not_reported_as_clean(self):
        self.binary.write_bytes(b"not an ELF")
        self.manifest()
        result = self.audit()
        self.assertEqual(result.returncode, 0)
        self.assertIn("selected artifact is not an ELF", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)


if __name__ == "__main__":
    unittest.main()
