"""Regression for libcgate COPY relocations from a digest-bound run manifest."""
import hashlib
import json
import os
from pathlib import Path
import platform
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


@unittest.skipUnless(CC and READELF and platform.machine().lower() in {"x86_64", "amd64"},
                     "requires x86-64, a C compiler, and readelf")
class LibcgateCopyRelocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "sample.c"
        self.binary = self.root / "chall"

    def compile(self, source, pie=False):
        self.source.write_text(source, encoding="utf-8")
        mode = ["-fPIE", "-pie"] if pie else ["-fno-pie", "-no-pie"]
        subprocess.run([CC, "-O0", *mode, "-o", str(self.binary),
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

    def audit(self, env=None):
        return subprocess.run([sys.executable, str(LIBCGATE), str(self.root)],
                              text=True, capture_output=True, timeout=15, env=env)

    def test_copy_relocation_prints_executable_address(self):
        self.compile('#include <stdio.h>\nextern FILE *stdout;\nint main(void){return fprintf(stdout,"ok\\n") < 0;}\n')
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COPY relocations (executable-owned globals", result.stdout)
        original = subprocess.check_output([READELF, "-rW", str(self.binary)], text=True)
        match = re.search(r"^([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+R_X86_64_COPY\s+[^\n]*\sstdout@", original, re.M)
        self.assertIsNotNone(match, original)
        self.assertIn("stdout @ 0x%x [R_X86_64_COPY]" % int(match.group(1), 16), result.stdout)

    def test_pie_copy_relocation_uses_image_relative_address(self):
        self.compile('#include <stdio.h>\nextern FILE *stdout;\nint main(void){return fprintf(stdout,"ok\\n") < 0;}\n', pie=True)
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"stdout @ PIE\+0x[0-9a-f]+ \[R_X86_64_COPY\]")

    def test_missing_manifest_reports_unavailable(self):
        self.compile('#include <stdio.h>\nint main(void){return puts("ok") < 0;}\n')
        (self.root / "run.json").unlink()
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn("run.json is missing; COPY relocation scan unavailable", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)

    def test_non_copy_elf_does_not_claim_a_copy(self):
        self.compile('#include <stdio.h>\nint main(void){return puts("ok") < 0;}\n')
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("COPY relocations: none detected", result.stdout)
        self.assertNotIn("executable-owned globals", result.stdout)

    def test_elf_with_no_relocations_is_clean(self):
        assembly = self.root / "tiny.s"
        assembly.write_text(".global _start\n_start:\n mov $60, %rax\n xor %rdi, %rdi\n syscall\n")
        subprocess.run([CC, "-nostdlib", "-static", "-no-pie", "-o", str(self.binary),
                        str(assembly)], check=True, capture_output=True, timeout=15)
        self.manifest()
        result = self.audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("COPY relocations: none detected", result.stdout)

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
        self.assertEqual(result.returncode, 1)
        self.assertIn("selected artifact is not an ELF", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)

    def test_selected_symlink_is_rejected(self):
        self.compile('#include <stdio.h>\nint main(void){return puts("ok") < 0;}\n')
        self.binary.rename(self.root / "real-chall")
        self.binary.symlink_to("real-chall")
        result = self.audit()
        self.assertEqual(result.returncode, 1)
        self.assertIn("not an ordinary challenge-local file", result.stdout)

    def test_readelf_failure_reports_unavailable(self):
        self.compile('#include <stdio.h>\nint main(void){return puts("ok") < 0;}\n')
        fake_tools = self.root / "tools"
        fake_tools.mkdir()
        fake_readelf = fake_tools / "readelf"
        fake_readelf.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
        fake_readelf.chmod(0o755)
        result = self.audit(env={**os.environ, "PATH": str(fake_tools)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("COPY relocation scan unavailable: readelf failed (exit 7)", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)

    def test_unrecognized_readelf_output_reports_unavailable(self):
        self.compile('#include <stdio.h>\nextern FILE *stdout;\nint main(void){return fprintf(stdout,"ok\\n") < 0;}\n')
        fake_tools = self.root / "tools"
        fake_tools.mkdir()
        fake_readelf = fake_tools / "readelf"
        fake_readelf.write_text("#!/bin/sh\necho 'unexpected readelf format'\n", encoding="utf-8")
        fake_readelf.chmod(0o755)
        result = self.audit(env={**os.environ, "PATH": str(fake_tools)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("COPY relocation scan unavailable: readelf relocation output is unrecognized", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)

    def test_incomplete_readelf_output_reports_unavailable(self):
        self.compile('#include <stdio.h>\nextern FILE *stdout;\nint main(void){return fprintf(stdout,"ok\\n") < 0;}\n')
        fake_tools = self.root / "tools"
        fake_tools.mkdir()
        fake_readelf = fake_tools / "readelf"
        fake_readelf.write_text("#!/bin/sh\necho \"Relocation section '.rela.dyn' at offset 0x400 contains 1 entry:\"\n",
                                encoding="utf-8")
        fake_readelf.chmod(0o755)
        result = self.audit(env={**os.environ, "PATH": str(fake_tools)})
        self.assertEqual(result.returncode, 1)
        self.assertIn("COPY relocation scan unavailable: readelf relocation output is incomplete", result.stdout)
        self.assertNotIn("COPY relocations: none", result.stdout)


if __name__ == "__main__":
    unittest.main()
