import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.decomp_cache import write_meta


@unittest.skipUnless(shutil.which("timeout") or shutil.which("gtimeout"), "decomp requires timeout")
class DecompBoundedListTests(unittest.TestCase):
    def test_large_function_index_lists_top_60_without_sigpipe(self):
        """The producer must finish even when the visible list is bounded."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "challenge"
            binary.write_bytes(b"synthetic-index-fixture")
            ghidra = root / "ghidra"
            (ghidra / "Ghidra").mkdir(parents=True)
            (ghidra / "Ghidra" / "application.properties").write_text(
                "application.version=fixture\n", encoding="utf-8")
            cache = Path(str(binary) + ".decomp")
            cache.mkdir()
            count = 24000
            (cache / "_index.txt").write_text(
                "".join(f"{0x400000 + i:08x}\tfun_{i:05d}\t{i + 1}\n" for i in range(count)),
                encoding="utf-8")
            write_meta(str(cache), str(binary), str(ghidra),
                       str(ROOT / "bin" / "ghidra_scripts"), "complete")
            env = dict(os.environ, CTF_HOME=str(ROOT), GHIDRA_HOME=str(ghidra),
                       XDG_CONFIG_HOME=str(root / "config"))
            cmd = [str(ROOT / "bin" / "decomp"), str(binary)]
            listed = subprocess.run(cmd, env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(listed.returncode, 0, listed.stderr)
            lines = listed.stdout.splitlines()
            self.assertTrue(lines[0].startswith("# 함수 목록"))
            self.assertEqual(len(lines), 61)
            self.assertIn("fun_23999", lines[1])
            self.assertIn("fun_23940", lines[-1])

            machine = subprocess.run(
                [str(ROOT / "bin" / "decomp"), "--format", "json", str(binary)],
                env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(machine.returncode, 0, machine.stderr)
            doc = json.loads(machine.stdout)
            self.assertEqual((doc["status"], doc["total"], doc["visible"], doc["truncated"]),
                             ("ok", count, 60, count - 60))
            self.assertEqual(doc["functions"][0]["name"], "fun_23999")
            self.assertEqual(doc["functions"][-1]["name"], "fun_23940")


if __name__ == "__main__":
    unittest.main()
