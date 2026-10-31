"""concrete_verify must bound its child's output and lifetime (review #4).

The concrete-verify re-run feeds solver-recovered input into the real binary.
An adversarial or buggy target could flood stdout or fork a long-lived
descendant. The bounded runner caps captured output and kills the whole process
group on timeout so a forked grandchild cannot outlive the verification.
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_symsolve():
    path = str(ROOT / "solve" / "_template" / "rev" / "symsolve.py")
    loader = importlib.machinery.SourceFileLoader("symsolve_concrete_bound_test", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@unittest.skipUnless(os.name == "posix", "process-group kill is POSIX-only")
class ConcreteVerifyBound(unittest.TestCase):
    def setUp(self):
        self.symsolve = load_symsolve()

    def test_output_is_capped(self):
        cap = self.symsolve._CONCRETE_VERIFY_OUTPUT_CAP
        with tempfile.TemporaryDirectory() as d:
            flood = os.path.join(d, "flood.sh")
            Path(flood).write_text("#!/bin/sh\nyes AAAA | head -c %d\n" % (cap * 4))
            os.chmod(flood, 0o755)
            out, truncated, returncode = self.symsolve._run_bounded([flood], b"", timeout=15)
            self.assertLessEqual(len(out), cap)
            self.assertTrue(truncated)
            self.assertNotEqual(returncode, 0)

    def test_endless_output_stops_at_cap(self):
        with tempfile.TemporaryDirectory() as d:
            flood = os.path.join(d, "flood.sh")
            Path(flood).write_text("#!/bin/sh\nexec yes AAAA\n")
            os.chmod(flood, 0o755)
            start = time.monotonic()
            out, truncated, returncode = self.symsolve._run_bounded([flood], None, timeout=5)
            self.assertTrue(truncated)
            self.assertEqual(len(out), self.symsolve._CONCRETE_VERIFY_OUTPUT_CAP)
            self.assertNotEqual(returncode, 0)
            self.assertLess(time.monotonic() - start, 3)

    def test_truncated_success_prefix_never_verifies(self):
        cap = self.symsolve._CONCRETE_VERIFY_OUTPUT_CAP
        with tempfile.TemporaryDirectory() as d:
            script = os.path.join(d, "prefix.py")
            Path(script).write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stdout.buffer.write(b'GOOD' + b'A' * %d + b'BAD')\n"
                "sys.stdout.buffer.flush()\n" % cap)
            os.chmod(script, 0o755)
            ok, detail, returncode = self.symsolve.concrete_verify(
                script, [], None, [b"GOOD"], [b"BAD"])
            self.assertIsNone(ok, "a truncated prefix must not become a PASS")
            self.assertIn("cap", detail)

    def test_transient_nonblocking_stdin_backpressure_is_retried(self):
        real_write = os.write
        attempts = 0

        def write_after_eagain(fd, data):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise BlockingIOError(11, "temporarily unavailable")
            return real_write(fd, data)

        with mock.patch.object(self.symsolve.os, "write", side_effect=write_after_eagain):
            out, truncated, returncode = self.symsolve._run_bounded(["/bin/cat"], b"hello", timeout=5)
        self.assertEqual(out, b"hello")
        self.assertFalse(truncated)
        self.assertEqual(returncode, 0)
        self.assertGreaterEqual(attempts, 2)

    def test_exit_status_is_part_of_concrete_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            for name, ending, expected, verdict in (
                ("zero", "exit 0", 0, True),
                ("seven", "exit 7", 0, False),
                ("explicit_seven", "exit 7", 7, True),
                ("signal", "kill -TERM $$", 0, False),
                ("signal_with_expected_seven", "kill -TERM $$", 7, False),
            ):
                with self.subTest(name=name):
                    script = os.path.join(d, name + ".sh")
                    Path(script).write_text('#!/bin/sh\nprintf "GOOD\\n"\n' + ending + '\n')
                    os.chmod(script, 0o755)
                    ok, detail, returncode = self.symsolve.concrete_verify(
                        script, [], None, [b"GOOD"], [], expected_exit_code=expected)
                    self.assertEqual(ok, verdict)
                    self.assertEqual(returncode, 0 if name == "zero" else
                                     (7 if "seven" in name and not name.startswith("signal") else -15))
                    if not verdict:
                        self.assertIn("target exit", detail)

    def test_forked_descendant_is_killed_on_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            marker = os.path.join(d, "alive.marker")
            script = os.path.join(d, "fork.sh")
            # Background grandchild would write the marker after 3s; the parent
            # then blocks. A 1s timeout must kill the whole group so the marker
            # is never created.
            Path(script).write_text(
                "#!/bin/sh\n( sleep 3; echo alive > %s ) &\nsleep 30\n" % marker)
            os.chmod(script, 0o755)
            start = time.time()
            with self.assertRaises(subprocess.TimeoutExpired):
                self.symsolve._run_bounded([script], b"", timeout=1)
            self.assertLess(time.time() - start, 5)
            time.sleep(4)
            self.assertFalse(os.path.exists(marker),
                             "forked descendant survived the timeout kill")


if __name__ == "__main__":
    unittest.main()
