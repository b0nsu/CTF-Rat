"""COPY-relocation facts: shared scanner + rat query pwn attention wiring (#98)."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))


class SharedScanner(unittest.TestCase):
    def test_non_elf_is_warning_not_empty(self):
        from ratlib.copy_reloc import copy_relocations
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"not an elf")
            p = f.name
        try:
            res, warn = copy_relocations(p)
            self.assertIsNone(res)
            self.assertIn("not an ELF", warn)
        finally:
            os.unlink(p)

    def test_real_binary_with_copy_relocs(self):
        from ratlib.copy_reloc import copy_relocations
        # find a system binary that has COPY relocations (readelf-backed)
        if not __import__("shutil").which("readelf"):
            self.skipTest("readelf unavailable")
        found = None
        for cand in ("/bin/ls", "/usr/bin/python3", "/bin/bash"):
            real = os.path.realpath(cand)
            if not os.path.exists(real):
                continue
            res, warn = copy_relocations(real)
            if res:
                found = (real, res)
                break
        if not found:
            self.skipTest("no system binary with COPY relocations found")
        real, res = found
        for addr, sym, kind in res:
            self.assertTrue(kind.endswith("_COPY"))
            self.assertTrue(addr.startswith("0x") or addr.startswith("PIE+0x"))


if __name__ == "__main__":
    unittest.main()
