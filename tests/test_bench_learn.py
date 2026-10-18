"""Regression for the benchmark + compounding-loop tooling (plans/BENCHMARK_LEARNING_LOOP.md).

Covers: ratbench selftest, pklearn selftest, and the STATE v2 failure.classified
controlled-vocabulary (fail-closed enum) added for L1.
"""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)


def _run(*argv):
    return subprocess.run([sys.executable, *argv], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, cwd=ROOT, timeout=180)


class BenchLearnSelftests(unittest.TestCase):
    def test_ratbench_selftest(self):
        p = _run(os.path.join(BIN, "ratbench"), "selftest")
        self.assertEqual(p.returncode, 0, p.stdout.decode())
        self.assertIn(b"ratbench selftest: OK", p.stdout)

    def test_ratbench_run_route_accuracy(self):
        # Mode A must route every synthetic entry correctly (verifiers may skip w/o gcc/angr).
        p = _run(os.path.join(BIN, "ratbench"), "run")
        self.assertEqual(p.returncode, 0, p.stdout.decode())

    def test_pklearn_selftest(self):
        p = _run(os.path.join(BIN, "pklearn"), "selftest")
        self.assertEqual(p.returncode, 0, p.stdout.decode())
        self.assertIn(b"pklearn selftest: OK", p.stdout)


class FailureClassVocabulary(unittest.TestCase):
    def test_enum_is_fail_closed(self):
        from ratlib.state_v2 import Stream, FAILURE_CLASSES
        self.assertEqual(
            FAILURE_CLASSES,
            {"route-miss", "offset-wrong", "libc-mismatch", "env", "tooling-gap", "timeout", "other"},
        )
        with tempfile.TemporaryDirectory() as d:
            st = Stream(d)
            st.append("run.initialized", {"challenge": "x"})
            # valid class accepted, materialized into the view's failures list
            st.append("failure.classified", {"failure_id": "f1", "class": "route-miss", "note": "n"})
            view = st.view()
            self.assertEqual(len(view["failures"]), 1)
            self.assertEqual(view["failures"][0]["class"], "route-miss")
            # invalid class rejected fail-closed
            with self.assertRaises(ValueError):
                st.append("failure.classified", {"failure_id": "f2", "class": "made-up", "note": "n"})


if __name__ == "__main__":
    unittest.main()
