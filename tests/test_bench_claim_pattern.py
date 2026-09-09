import importlib.machinery
import importlib.util
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)

from ratlib.bench_suite import SuiteValidationError, validate_suite


def _load_ratbench():
    loader = importlib.machinery.SourceFileLoader("_ratbench_claim_pattern", os.path.join(BIN, "ratbench"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


RATBENCH = _load_ratbench()


def _entry(claim_pattern=None):
    verify = {"kind": "rat-verify-pass"}
    if claim_pattern is not None:
        verify["claim_pattern"] = claim_pattern
    return {
        "id": "claim-pattern-01",
        "track": "rev",
        "expected_route": "rev-checker",
        "difficulty": 1,
        "corpus": "private",
        "capabilities": ["checker"],
        "redistributable": False,
        "dir": "bench/artifacts/checker-basic-01",
        "binary": "chall.bin",
        "route_fixture": "route.json",
        "verify": verify,
        "env": {"needs_libc": False},
    }


class ClaimPatternTests(unittest.TestCase):
    def test_legacy_suite_keeps_flag_prefix_detector(self):
        entry = _entry()
        self.assertTrue(RATBENCH._flag_claimed(entry, "answer: FLAG{abc123}"))
        self.assertFalse(RATBENCH._flag_claimed(entry, "answer: CTF{abc123}"))

    def test_real_ctf_prefix_can_be_declared_per_entry(self):
        entry = _entry(r"(?i)ctf\{[^\r\n{}]+\}")
        self.assertTrue(RATBENCH._flag_claimed(entry, "CTF{official-format}"))
        self.assertTrue(RATBENCH._flag_claimed(entry, "ctf{binary-output-format}"))
        self.assertFalse(RATBENCH._flag_claimed(entry, "FLAG{different-format}"))

    def test_invalid_claim_pattern_fails_suite_preflight(self):
        doc = {"schema": "rat.bench-suite/v1", "entries": [_entry("[")]}
        with self.assertRaisesRegex(SuiteValidationError, "verify.claim_pattern is invalid"):
            validate_suite(doc)


if __name__ == "__main__":
    unittest.main()
