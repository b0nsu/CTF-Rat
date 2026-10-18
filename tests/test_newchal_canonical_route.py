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

    def _run_scaffold(self, route_rc, artifact_bytes=b"\x7fELFtest-fixture",
                      analysis_failed=False):
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
            (module_dir / "raw_loader.py").write_text(
                'def inspect_raw(path):\n    return {"kind": "unknown"}\n', encoding="utf-8")
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
                             "if [ \"$ROUTE_ANALYSIS_FAILED\" = 1 ]; then\n"
                             "  echo '{\"commitment\":\"unknown\",\"diagnostics\":[{\"code\":\"analysis_failed\"}]}'\n"
                             "else\n"
                             "  echo '{\"commitment\":\"provisional\",\"diagnostics\":[]}'\n"
                             "fi\n"
                             "if [ \"$ROUTE_RC\" -ne 0 ]; then echo 'route unavailable' >&2; fi\n"
                             "exit \"$ROUTE_RC\"\n")

            artifact = root / "chall"
            artifact.write_bytes(artifact_bytes)
            args_file = root / "rat-args"
            env = os.environ.copy()
            env.update({"CTF_HOME": str(home), "RAT_ARGS": str(args_file),
                        "ROUTE_RC": str(route_rc),
                        "ROUTE_ANALYSIS_FAILED": "1" if analysis_failed else "0"})
            proc = subprocess.run(
                ["bash", str(bin_dir / "newchal"), "vm-fixture", str(artifact)],
                cwd=str(root), env=env, capture_output=True, text=True, timeout=30,
            )
            state = home / "solve" / "vm-fixture" / "state.md"
            manifest = home / "solve" / "vm-fixture" / "run.json"
            return (proc, args_file.read_text().splitlines() if args_file.exists() else [],
                    state.read_text() if state.exists() else "",
                    manifest.exists())

    def test_newchal_uses_canonical_route_not_recon(self):
        proc, args, state, manifest = self._run_scaffold(0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(args, ["route", "./chall", "--format", "json"])
        self.assertTrue(manifest)
        self.assertIn("=== rat route (provisional evidence) ===", proc.stdout)
        self.assertIn('"commitment":"provisional"', state)
        self.assertNotIn("ROUTE UNKNOWN", state)
        self.assertNotIn("LEGACY_RECON_INVOKED", proc.stdout + state)

    def test_route_failure_keeps_scaffold_but_does_not_fallback_to_recon(self):
        proc, args, state, manifest = self._run_scaffold(2)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(args, ["route", "./chall", "--format", "json"])
        self.assertTrue(manifest)
        self.assertIn("route unavailable", state)
        self.assertIn("ROUTE UNKNOWN", proc.stdout)
        self.assertIn("ROUTE UNKNOWN", state)
        self.assertNotIn("LEGACY_RECON_INVOKED", proc.stdout + state)

    def test_pe_artifact_does_not_force_elf_only_fast_route(self):
        proc, args, state, manifest = self._run_scaffold(0, b"MZ" + b"\0" * 62)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(args, ["route", "./chall", "--format", "json"])
        self.assertTrue(manifest)

    def test_route_exit_zero_with_analysis_failure_is_degraded(self):
        proc, args, state, manifest = self._run_scaffold(0, analysis_failed=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(args, ["route", "./chall", "--format", "json"])
        self.assertTrue(manifest)
        self.assertIn('"code":"analysis_failed"', state)
        self.assertIn("ROUTE UNKNOWN", proc.stdout)
        self.assertIn("ROUTE UNKNOWN", state)


class NewchalWasmScaffoldTests(unittest.TestCase):
    """R2-7: a valid WebAssembly core module must take the Wasm branch and never
    get a pwntools ELF() exploit template."""

    @staticmethod
    def _executable(path, source):
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def _scaffold_wasm(self, artifact_bytes):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            home = root / "ctf-home"
            bin_dir = home / "bin"
            module_dir = bin_dir / "ratlib"
            module_dir.mkdir(parents=True)
            (module_dir / "__init__.py").write_text("", encoding="utf-8")
            (home / "solve" / "_template").mkdir(parents=True)
            (home / "solve" / "_template" / "state.md").write_text("# fixture\n")
            shutil.copy2(ROOT / "bin" / "newchal", bin_dir / "newchal")
            # Real wasm inspector; stubbed ELF/raw classifiers so classification
            # falls through to the wasm check.
            shutil.copy2(ROOT / "bin" / "ratlib" / "wasm.py", module_dir / "wasm.py")
            (module_dir / "kernel_identity.py").write_text(
                'def inspect(path):\n    return {"kind": "unknown"}\n', encoding="utf-8")
            (module_dir / "raw_loader.py").write_text(
                'def inspect_raw(path):\n    return {"kind": "unknown"}\n', encoding="utf-8")
            (module_dir / "run_manifest.py").write_text(
                'from pathlib import Path\n'
                'def materialize_for_solve(source, destination, **kwargs):\n'
                '    Path(destination).write_text("{}\\n")\n', encoding="utf-8")
            self._executable(bin_dir / "ctfguard", "#!/bin/sh\nexit 0\n")
            self._executable(bin_dir / "libcgate", "#!/bin/sh\nexit 0\n")
            self._executable(bin_dir / "recon",
                             "#!/bin/sh\necho LEGACY_RECON_INVOKED\nexit 97\n")
            # If the ELF route branch is reached, this stub records that it was.
            self._executable(bin_dir / "rat",
                             "#!/bin/sh\necho RAT_ROUTE_INVOKED\nexit 0\n")

            artifact = root / "mod.wasm"
            artifact.write_bytes(artifact_bytes)
            env = os.environ.copy()
            env.update({"CTF_HOME": str(home)})
            proc = subprocess.run(
                ["bash", str(bin_dir / "newchal"), "wasm-fixture", str(artifact)],
                cwd=str(root), env=env, capture_output=True, text=True, timeout=30,
            )
            exploit = home / "solve" / "wasm-fixture" / "exploit.py"
            return proc, (exploit.read_text() if exploit.exists() else "")

    def test_valid_wasm_takes_wasm_branch_without_elf(self):
        proc, exploit = self._scaffold_wasm(b"\0asm\x01\0\0\0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WebAssembly core module", proc.stdout)
        self.assertNotIn("RAT_ROUTE_INVOKED", proc.stdout)  # ELF route not taken
        self.assertNotIn("LEGACY_RECON_INVOKED", proc.stdout)
        self.assertTrue(exploit)
        # No pwntools ELF() *loader call* in the generated exploit (the comment
        # warning against ELF() is expected; the from pwn import * template is not).
        self.assertNotIn("from pwn import", exploit)
        self.assertNotIn('ELF("./', exploit)
        self.assertIn("from ratlib import wasm", exploit)

    def test_non_wasm_unknown_still_uses_elf_route(self):
        # A non-ELF, non-WASM blob falls back to the ELF/route branch (unchanged).
        proc, exploit = self._scaffold_wasm(b"not a wasm module at all")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("RAT_ROUTE_INVOKED", proc.stdout)
        self.assertNotIn("WebAssembly core module", proc.stdout)
        self.assertIn('ELF("./', exploit)


if __name__ == "__main__":
    unittest.main()
