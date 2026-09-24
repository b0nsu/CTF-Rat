import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "bin"))
from ratlib import angr_runtime


class AngrRuntimeTests(unittest.TestCase):
    def test_default_venv_and_missing_venv(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"CTF_HOME": root}, clear=False):
            with patch.dict(os.environ, {"RAT_ANGR_PYTHON": ""}):
                self.assertIsNone(angr_runtime.configured_python())
                interpreter = pathlib.Path(root, ".venv-angr", "bin", "python")
                interpreter.parent.mkdir(parents=True)
                interpreter.write_text("#!/bin/sh\n")
                interpreter.chmod(0o755)
                self.assertEqual(angr_runtime.configured_python(), str(interpreter))

    def test_invalid_override_fails_closed(self):
        with patch.dict(os.environ, {"RAT_ANGR_PYTHON": "/nonexistent/angr-python"}):
            with self.assertRaisesRegex(ValueError, "not an executable"):
                angr_runtime.configured_python()

    def test_reexec_preserves_script_and_args_across_venv_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            interpreter = pathlib.Path(root, "python")
            interpreter.symlink_to(sys.executable)
            script = pathlib.Path(root, "entry.py")
            script.write_text("pass\n")
            with patch.object(angr_runtime, "configured_python", return_value=str(interpreter)), \
                 patch.object(angr_runtime.os, "execve") as execv:
                angr_runtime.reexec_for_angr(str(script), ["--arg", "value with spaces"])
            self.assertEqual(execv.call_args.args[:2], (
                str(interpreter), [str(interpreter), os.path.realpath(script), "--arg", "value with spaces"]))
            self.assertEqual(execv.call_args.args[2]["RAT_ANGR_REEXEC_TARGET"], os.path.realpath(interpreter))

    def test_reexec_skips_current_interpreter(self):
        with patch.object(angr_runtime, "configured_python", return_value=os.path.abspath(sys.executable)), \
             patch.object(angr_runtime.os, "execve") as execv:
            angr_runtime.reexec_for_angr("entry.py", [])
        execv.assert_not_called()


if __name__ == "__main__":
    unittest.main()
