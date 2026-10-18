"""Deterministic regressions for newchal source generation and filename trust."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NewchalSecurityTests(unittest.TestCase):
    def test_scaffold_matrix_and_hostile_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "kit"
            tools = home / "bin"
            modules = tools / "ratlib"
            template = home / "solve" / "_template"
            modules.mkdir(parents=True)
            template.mkdir(parents=True)
            shutil.copy2(ROOT / "bin" / "newchal", tools / "newchal")
            (template / "state.md").write_text(
                "# {{NAME}}\nbinary={{BIN}}\nremote={{REMOTE}}\n", encoding="utf-8")
            (modules / "kernel_identity.py").write_text(
                'def inspect(path): return {"kind": "elf"}\n', encoding="utf-8")
            (modules / "raw_loader.py").write_text(
                'def inspect_raw(path): return {"kind": "unknown"}\n', encoding="utf-8")
            (modules / "run_manifest.py").write_text(
                'from pathlib import Path\n'
                'def materialize_for_solve(source, destination, **kwargs):\n'
                '    Path(destination).write_text("{}\\n")\n', encoding="utf-8")
            for name in ("ctfguard", "libcgate", "recon"):
                path = tools / name
                path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                path.chmod(0o755)
            route = tools / "rat"
            route.write_text('#!/bin/sh\necho \'{"diagnostics":[]}\'\n', encoding="utf-8")
            route.chmod(0o755)
            binary = base / "chall"
            binary.write_bytes(b"\x7fELFfixture")
            libc = base / "libc_input"
            libc.write_bytes(b"fixture libc")
            env = {**os.environ, "CTF_HOME": str(home)}
            for has_libc in (False, True):
                for has_remote in (False, True):
                    name = "case_%d_%d" % (has_libc, has_remote)
                    argv = ["bash", str(tools / "newchal"), name, str(binary)]
                    if has_libc or has_remote:
                        argv.append(str(libc) if has_libc else "")
                    if has_remote:
                        argv.append("example.test:31337")
                    result = subprocess.run(argv, env=env, capture_output=True,
                                            text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    solve = home / "solve" / name
                    source = solve / "exploit.py"
                    compiled = subprocess.run(
                        ["python3", "-m", "py_compile", str(source)],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    self.assertTrue((solve / "run.json").exists())
                    self.assertEqual("libc = ELF" in source.read_text(), has_libc)
                    self.assertEqual("return remote" in source.read_text(), has_remote)
                    self.assertIn("binary=chall", (solve / "state.md").read_text())
            alias = base / "safe_alias"
            alias.symlink_to(binary)
            linked = subprocess.run(
                ["bash", str(tools / "newchal"), "linked", str(alias)],
                env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            self.assertIn('ELF("./chall"', (home / "solve" / "linked" / "exploit.py").read_text())
            hostile = ('evil"\nprint(123)', "bad\\name", "bad name", "bad\nname",
                       "bad#name", "bad&name")
            for index, filename in enumerate(hostile):
                path = base / filename
                path.write_bytes(b"\x7fELFfixture")
                result = subprocess.run(
                    ["bash", str(tools / "newchal"), "bad_%d" % index, str(path)],
                    env=env, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2, (filename, result.stderr))
                self.assertFalse((home / "solve" / ("bad_%d" % index)).exists())


if __name__ == "__main__":
    unittest.main()
