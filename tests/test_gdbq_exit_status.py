"""gdbq must propagate gdb's own exit status, not the trailing filter's (review #5).

A gdb session that fails (undefined command, batch error) or times out must
surface a non-zero exit so the trusted-verifier evidence gate (contracts runner,
status == 'ok' only when exit_code == 0) never mints evidence from a failed
debug session. A successful session whose output is fully removed by the display
filter must still exit 0.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GDBQ = ROOT / "bin" / "gdbq"


@unittest.skipUnless(shutil.which("gdb"), "gdb not installed (env-skip)")
class GdbqExitStatus(unittest.TestCase):
    def _run(self, *argv, env=None):
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        return subprocess.run(["bash", str(GDBQ), *argv], capture_output=True,
                              text=True, timeout=90, env=full_env)

    def test_undefined_command_exits_nonzero(self):
        # gdb returns rc=1 for an undefined command in -batch; gdbq must not
        # swallow it into the filter's status.
        r = self._run("/bin/true", "this_is_not_a_gdb_command")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_valid_session_with_filtered_output_exits_zero(self):
        # `quit` produces only banner lines that the grep filter removes; the
        # session still succeeded, so the exit code stays 0.
        r = self._run("/bin/true", "quit")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_valid_session_preserves_requested_output(self):
        r = self._run("/bin/true", "print 1+1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"\$1 = (?:2|0x2)\b")

    def test_timeout_is_propagated(self):
        r = self._run("/bin/true", "shell sleep 10", env={"GDBQ_TIMEOUT": "1"})
        self.assertEqual(r.returncode, 124, r.stdout + r.stderr)


class GdbqOutputCap(unittest.TestCase):
    def test_cap_is_enforced_while_gdb_writes(self):
        with tempfile.TemporaryDirectory() as root:
            fake_gdb = Path(root) / "gdb"
            fake_gdb.write_text("#!/bin/sh\nhead -c 200000 /dev/zero\n")
            fake_gdb.chmod(0o755)
            env = dict(os.environ, PATH=root + os.pathsep + os.environ["PATH"],
                       TMPDIR=root, GDBQ_MAX_BYTES="1024")
            result = subprocess.run(["bash", str(GDBQ), "/bin/true"], env=env,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 122, result.stderr)
            self.assertIn(b"exceeded", result.stderr)
            self.assertEqual(list(Path(root).glob("gdbq.*")), [])


if __name__ == "__main__":
    unittest.main()
