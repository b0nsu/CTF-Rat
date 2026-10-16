"""Regression for Issue #100: newchal must not invoke legacy recon triage.

The scaffold is exercised with a stub toolchain so the test is independent
of pwntools, angr, Ghidra, local libc, and an actual CTF binary.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class NewchalCanonicalRouteTests(unittest.TestCase):
    @staticmethod
    def _executable(path, source):
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def _run_scaffold(self, route_rc):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            home = root / "ctf-home"
            bin_dir = home / "bin"
            module_dir = bin_dir / "ratlib"
            module_dir.mkdir(parents=True)
            (home / "solve" / "_template").mkdir(parents=True)
            (home / "solve" / "_template" / "state.md").write_text("# fixture\n")
            shutil.copy2(ROOT / "bin" / "newchal", bin_dir / "newchal")

            (module_dir / "kernel_identity.py").write_text(
                'def inspect(path):\n    return {"kind": "elf"}\n', encoding="utf-8")
            (module_dir / "run_manifest.py").write_text(
                'from pathlib import Path\n'
                'def materialize_for_solve(source, destination, **kwargs):\n'
                '    Path(destination).write_text("{}\\n")\n', encoding="utf-8")

            self._executable(bin_dir / "ctfguard", "#!/bin/sh\nexit 0\n")
            self._executable(bin_dir / "libcgate", "#!/bin/sh\nexit 0\n")
            self._executable(bin_dir / "recon",
                             "#!/bin/sh\necho LEGACY_RECON_INVOKED\nexit 97\n")
            self._executable(bin_dir / "rat",
                             "#!/bin/sh\n"
                             "printf '%s\\n' \"$@\" > \"$RAT_ARGS\"\n"
                             "echo 'COMMITMENT  provisional'\n"
                             "echo 'LEADS       checker, vm'\n"
                             "if [ \"$ROUTE_RC\" -ne 0 ]; then echo 'route unavailable' >&2; fi\n"
                             "exit \"$ROUTE_RC\"\n")

            artifact = root / "chall"
            artifact.write_bytes(b"\x7fELFtest-fixture")
            args_file = root / "rat-args"
            env = os.environ.copy()
            env.update({"CTF_HOME": str(home), "RAT_ARGS": str(args_file),
                        "ROUTE_RC": str(route_rc)})
            proc = subprocess.run(
                ["bash", str(bin_dir / "newchal"), "vm-fixture", str(artifact)],
                cwd=str(root), env=env, capture_output=True, text=True, timeout=30,
            )
            state = home / "solve" / "vm-fixture" / "state.md"
            manifest = home / "solve" / "vm-fixture" / "run.json"
            return (proc, args_file.read_text().splitlines() if args_file.exists() else [],
                    state.read_text() if state.exists() else "",
                    manifest.exists())

    def test_newchal_uses_canonical_fast_route_not_recon(self):
        proc, args, state, manifest = self._run_scaffold(0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(args, ["route", "./chall", "--fast"])
        self.assertTrue(manifest)
        self.assertIn("=== rat route (provisional evidence) ===", proc.stdout)
        self.assertIn("COMMITMENT  provisional", state)
        self.assertNotIn("LEGACY_RECON_INVOKED", proc.stdout + state)

    def test_route_failure_keeps_scaffold_but_does_not_fallback_to_recon(self):
        proc, args, state, manifest = self._run_scaffold(2)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(args, ["route", "./chall", "--fast"])
        self.assertTrue(manifest)
        self.assertIn("route unavailable", state)
        self.assertIn("ROUTE UNKNOWN", proc.stdout)
        self.assertIn("ROUTE UNKNOWN", state)
        self.assertNotIn("LEGACY_RECON_INVOKED", proc.stdout + state)


if __name__ == "__main__":
    unittest.main()
