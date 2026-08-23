import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.context_snapshot import snapshot


class ContextSnapshotTests(unittest.TestCase):
    def sample_view(self):
        return {
            "observations": {
                "obs_direct": {
                    "kind": "register",
                    "value": {"rip": "0x401234"},
                    "quality": {"level": "direct"},
                    "validity": {"state": "active"},
                },
                "obs_invalid": {
                    "kind": "string",
                    "value": "stale",
                    "quality": {"level": "direct"},
                    "validity": {"state": "invalidated"},
                },
            },
            "findings": {
                "f_confirmed": {"state": "confirmed", "title": "checker reaches success branch", "confidence": 0.97},
                "f_proposed": {"state": "proposed", "title": "possible xor transform", "confidence": 0.55},
            },
            "primitives": {
                "p_pass": {"status": "pass", "kind": "controlled branch"},
            },
            "hypotheses": {
                "h1": {"text": "input is transformed before compare"},
            },
            "ruled_out": {
                "direct-strcmp": {"text": "no direct strcmp path"},
            },
            "unknowns": {
                "u1": {"text": "transform semantics"},
            },
            "next_probes": [
                {"probe": "decompile-transform", "text": "inspect transform function"},
            ],
        }

    def test_prioritizes_verified_state_and_omits_invalid_observations(self):
        result = snapshot(self.sample_view(), budget_tokens=1200)
        text = result["text"]
        self.assertIn("f_confirmed", text)
        self.assertIn("p_pass", text)
        self.assertIn("decompile-transform", text)
        self.assertIn("obs_direct", text)
        self.assertNotIn("obs_invalid", text)
        self.assertLessEqual(result["used_bytes"], result["max_bytes"])

    def test_tight_budget_is_hard_byte_bounded(self):
        result = snapshot(self.sample_view(), budget_tokens=64, max_bytes=256)
        self.assertLessEqual(len(result["text"].encode("utf-8")), 256)
        self.assertGreater(result["omitted"], 0)
        self.assertIn("f_confirmed", result["text"])

    def test_rejects_invalid_budget(self):
        with self.assertRaises(ValueError):
            snapshot(self.sample_view(), budget_tokens=0)
        with self.assertRaises(ValueError):
            snapshot(self.sample_view(), max_bytes=0)


if __name__ == "__main__":
    unittest.main()
