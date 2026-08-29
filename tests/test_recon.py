import pathlib
import contextlib
import io
import os
import runpy
import subprocess
import sys
import types
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "bin" / "recon"


class ReconTests(unittest.TestCase):
    def install_runner_stub(self, root):
        runner = types.ModuleType("ratlib.runner")
        class _Stream:
            def __init__(self, data):
                self.preview = data
        class _Result:
            def __init__(self, proc):
                self.stdout = _Stream(proc.stdout)
                self.stderr = _Stream(proc.stderr)
                self.exit_code = proc.returncode
        def run(argv, **kwargs):
            return _Result(subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        runner.run = run
        return runner

    def run_recon(self, root, fixture, *extra):
        runner = self.install_runner_stub(root)
        old_argv = sys.argv[:]
        old_path = sys.path[:]
        old_modules = {name: sys.modules.get(name) for name in ("ratlib.runner", "pwn")}
        old_env = os.environ.copy()
        stdout, stderr = io.StringIO(), io.StringIO()
        try:
            sys.argv = [str(TOOL), str(fixture), *extra]
            sys.path.insert(0, str(root))
            sys.modules["ratlib.runner"] = runner
            sys.modules.pop("pwn", None)
            os.environ["PATH"] = str(root) + os.pathsep + old_env.get("PATH", "")
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    runpy.run_path(str(TOOL), run_name="__main__")
                    code = 0
                except SystemExit as exc:
                    code = exc.code or 0
        finally:
            sys.argv = old_argv
            sys.path[:] = old_path
            for name, module in old_modules.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
            os.environ.clear()
            os.environ.update(old_env)
        return types.SimpleNamespace(returncode=code, stdout=stdout.getvalue(), stderr=stderr.getvalue())

    def test_pe_with_shell_metacharacters_in_path_is_routed_to_rev(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fixture = root / "sample 'quoted name'.exe"
            # Minimal PE32 image: DOS header, PE offset, signature, and an
            # i386 COFF header.  The pwn stub must never parse this fixture.
            image = bytearray(256)
            image[:2] = b"MZ"
            image[0x3C:0x40] = (0x80).to_bytes(4, "little")
            image[0x80:0x84] = b"PE\0\0"
            image[0x84:0x86] = (0x14C).to_bytes(2, "little")
            fixture.write_bytes(image)
            (root / "pwn.py").write_text(
                "class _Context: log_level = None\n"
                "context = _Context()\n"
                "class ELF:\n    def __init__(self, *args, **kwargs): raise AssertionError('ELF parser called')\n",
                encoding="utf-8",
            )
            file_tool = root / "file"
            file_tool.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "assert sys.argv[1:] == ['--', %r]\n"
                "print(sys.argv[2] + ': PE32 executable (console) Intel 80386')\n" % str(fixture),
                encoding="utf-8",
            )
            file_tool.chmod(0o755)
            result = self.run_recon(root, fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PE/Windows", result.stdout)

    def test_stripped_fast_candidate_downgrades_confidence_with_tier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fixture = root / "a.out"
            fixture.write_bytes(b"ELF")
            (root / "pwn.py").write_text(
                "class _Context: log_level = None\n"
                "context = _Context()\n"
                "class ELF:\n"
                "    def __init__(self, *args, **kwargs):\n"
                "        self.symbols={'gets':1,'system':2}\n"
                "        self.plt={}\n"
                "        self.functions={}\n"
                "        self.pie=False; self.canary=False; self.nx=True; self.relro='Partial'\n",
                encoding="utf-8",
            )
            file_tool = root / "file"
            file_tool.write_text("#!/usr/bin/env sh\nprintf '%s: ELF 64-bit executable, stripped\\n' \"$2\"\n", encoding="utf-8")
            file_tool.chmod(0o755)
            strings_tool = root / "strings"
            strings_tool.write_text("#!/usr/bin/env sh\nprintf '/bin/sh\\n'\n", encoding="utf-8")
            strings_tool.chmod(0o755)
            result = self.run_recon(root, fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TRIAGE: 🟡 STANDARD", result.stdout)
        self.assertIn("확신도: 중간", result.stdout)
        self.assertNotIn("STANDARD  | 확신도: 높음", result.stdout)


    def test_format_json_emits_machine_view_without_korean_text(self):
        import json as _json
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fixture = root / "a.out"
            fixture.write_bytes(b"ELF")
            (root / "pwn.py").write_text(
                "class _Context: log_level = None\n"
                "context = _Context()\n"
                "class ELF:\n"
                "    def __init__(self, *args, **kwargs):\n"
                "        self.symbols={'gets':1,'system':2,'win':3}\n"
                "        self.plt={}\n"
                "        self.functions={}\n"
                "        self.pie=False; self.canary=False; self.nx=True; self.relro='Partial'\n",
                encoding="utf-8",
            )
            file_tool = root / "file"
            file_tool.write_text("#!/usr/bin/env sh\nprintf '%s: ELF 64-bit executable, not stripped\\n' \"$2\"\n", encoding="utf-8")
            file_tool.chmod(0o755)
            strings_tool = root / "strings"
            strings_tool.write_text("#!/usr/bin/env sh\nprintf '/bin/sh\\n'\n", encoding="utf-8")
            strings_tool.chmod(0o755)
            result = self.run_recon(root, fixture, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        doc = _json.loads(result.stdout)
        self.assertEqual(doc["schema"], "rat.recon/v1")
        self.assertEqual(doc["status"], "ok")
        self.assertIn(doc["triage"]["tier"], {"fast", "standard", "hard"})
        # language-agnostic keys let a machine consumer branch without parsing Korean
        self.assertIn(doc["triage"]["confidence_key"], {"low", "mid", "high"})
        self.assertIn(doc["triage"]["recommendation_key"], {"solve", "deprioritize"})
        self.assertIsInstance(doc["protections"]["nx"], bool)
        # machine view must be free of the Korean prose the text mode prints
        self.assertNotIn("확신도", result.stdout)
        self.assertNotIn("추정 기법", result.stdout)

    def test_format_json_routes_pe(self):
        import json as _json
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            fixture = root / "a.exe"
            fixture.write_bytes(b"MZ")
            (root / "pwn.py").write_text(
                "class _Context: log_level = None\ncontext = _Context()\n"
                "class ELF:\n    def __init__(self, *a, **k): raise AssertionError('should not parse')\n",
                encoding="utf-8",
            )
            file_tool = root / "file"
            file_tool.write_text("#!/usr/bin/env sh\nprintf '%s: PE32 executable\\n' \"$2\"\n", encoding="utf-8")
            file_tool.chmod(0o755)
            result = self.run_recon(root, fixture, "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(_json.loads(result.stdout)["status"], "pe")


if __name__ == "__main__":
    unittest.main()
