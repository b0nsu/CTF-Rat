#!/usr/bin/env python3
"""Regression coverage for challenge-scoped pkflag (Issue #99)."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PKFLAG = Path(__file__).resolve().parents[1] / "bin" / "pkflag"
HEX = r"DH\{[0-9a-f]{4,}\}"
VM = "DH{vm_handlers_are_easy_order_is_key}"


class PkflagTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / "solve" / "alpha").mkdir(parents=True)
        (self.home / "solve" / "beta").mkdir()
        (self.home / "FLAG_FORMAT").write_text(HEX + "\n")  # stale legacy config
        self.activate("alpha")

    def activate(self, chal):
        if chal is None:
            (self.home / "ACTIVE.json").unlink(missing_ok=True)
        else:
            (self.home / "ACTIVE.json").write_text(json.dumps({"chal": chal}))

    def run_flag(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(PKFLAG), *args],
            cwd=cwd or self.home, env={**os.environ, "CTF_HOME": str(self.home)},
            capture_output=True, text=True, timeout=5,
        )

    def test_challenge_scope_isolation_and_no_implicit_global_fallback(self):
        self.assertEqual(self.run_flag("--set", HEX).returncode, 0)
        self.assertEqual(self.run_flag("DH{deadbeef}").returncode, 0)
        self.assertEqual(self.run_flag(VM).returncode, 1)
        self.activate("beta")
        self.assertEqual(self.run_flag(VM).returncode, 0)
        self.assertEqual(self.run_flag("--show").stdout.strip(), "(미설정)")
        self.assertEqual(self.run_flag("--set", r"DH\{[A-Za-z0-9_]+\}").returncode, 0)
        self.assertEqual(self.run_flag(VM).returncode, 0)
        self.activate("alpha")
        self.assertEqual(self.run_flag(VM).returncode, 1)
        self.assertEqual((self.home / "FLAG_FORMAT").read_text().strip(), HEX)

    def test_original_issue_vm_candidate_passes_with_no_challenge_format(self):
        self.assertEqual(self.run_flag(VM).returncode, 0)
        self.assertIn("format-only", self.run_flag(VM).stdout)

    def test_global_format_is_explicit_opt_in(self):
        self.assertEqual(self.run_flag("--global", "--show").stdout.strip(), HEX)
        self.assertEqual(self.run_flag("--global", VM).returncode, 1)
        self.assertEqual(self.run_flag("--global", "--set", r"DH\{[A-Za-z0-9_]+\}").returncode, 0)
        self.assertEqual(self.run_flag("--global", VM).returncode, 0)
        self.assertEqual(self.run_flag(VM).returncode, 0)

    def test_set_without_scope_is_rejected_without_global_write(self):
        self.activate(None)
        before = (self.home / "FLAG_FORMAT").read_bytes()
        self.assertEqual(self.run_flag("--set", r"X\{.+\}").returncode, 2)
        self.assertEqual((self.home / "FLAG_FORMAT").read_bytes(), before)
        self.assertEqual(self.run_flag(VM).returncode, 0)

    def test_explicit_chal_without_active_and_conflict(self):
        self.activate(None)
        self.assertEqual(self.run_flag("--chal", "alpha", "--set", HEX).returncode, 0)
        self.assertEqual(self.run_flag("--chal", "alpha", "DH{deadbeef}").returncode, 0)
        self.activate("beta")
        self.assertEqual(self.run_flag("--chal", "alpha", VM).returncode, 2)
        self.assertEqual(self.run_flag("--chal", "../alpha", VM).returncode, 2)
        self.assertEqual(self.run_flag("--chal", "missing", VM).returncode, 2)

    def test_cwd_active_mismatch_fails_closed(self):
        self.assertEqual(self.run_flag(VM, cwd=self.home / "solve" / "beta").returncode, 2)

    def test_cwd_without_active_uses_local_challenge(self):
        self.activate(None)
        self.assertEqual(self.run_flag("--set", HEX, cwd=self.home / "solve" / "alpha").returncode, 0)
        self.assertEqual(self.run_flag(VM, cwd=self.home / "solve" / "alpha").returncode, 1)
        self.assertEqual(self.run_flag(VM, cwd=self.home / "solve" / "beta").returncode, 0)

    def test_format_must_fullmatch(self):
        self.assertEqual(self.run_flag("--set", HEX).returncode, 0)
        self.assertEqual(self.run_flag("DH{deadbeef}TRAIL").returncode, 1)
        self.assertEqual(self.run_flag("PREFIXDH{deadbeef}").returncode, 1)

    def test_placeholder_and_legitimate_test_substring(self):
        self.assertEqual(self.run_flag("DH{fake_flag}").returncode, 1)
        self.assertIn("FAKE", self.run_flag("DH{fake_flag}").stdout)
        self.assertEqual(self.run_flag("DH{contest_winner}").returncode, 0)

    def test_bad_regex_and_empty_regex_cannot_replace_existing_file(self):
        fmt = self.home / "solve" / "alpha" / "FLAG_FORMAT"
        self.assertEqual(self.run_flag("--set", HEX).returncode, 0)
        before = fmt.read_bytes()
        self.assertEqual(self.run_flag("--set", "[").returncode, 2)
        self.assertEqual(self.run_flag("--set", "").returncode, 2)
        self.assertEqual(fmt.read_bytes(), before)

    def test_symlinked_challenge_directory_rejected(self):
        (self.home / "solve" / "escape").symlink_to(self.home / "solve" / "alpha", target_is_directory=True)
        self.activate("escape")
        self.assertEqual(self.run_flag("--set", HEX).returncode, 2)
        self.assertEqual(self.run_flag("--show").returncode, 2)

    def test_symlinked_format_file_cannot_import_another_scope(self):
        target = self.home / "FLAG_FORMAT"
        fmt = self.home / "solve" / "alpha" / "FLAG_FORMAT"
        fmt.symlink_to(target)
        for args in (("DH{deadbeef}",), ("--show",)):
            with self.subTest(args=args):
                result = self.run_flag(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("symlink", result.stderr)
        self.assertEqual(self.run_flag("--set", r"DH\{[A-Za-z0-9_]+\}").returncode, 0)
        self.assertFalse(fmt.is_symlink())
        self.assertEqual(target.read_text().strip(), HEX)


if __name__ == "__main__":
    unittest.main()
