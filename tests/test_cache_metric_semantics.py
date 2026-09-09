import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.metrics import aggregate


DIGEST = "sha256:" + "a" * 64


def envelope(*, status="ok", cache_state="miss"):
    return {
        "schema": "rat.tool-result/v1",
        "tool": {"name": "fixture", "build_digest": DIGEST},
        "status": status,
        "inputs": [],
        "parameters": {},
        "duration_ms": 0,
        "tool_name": "fixture",
        "cache_state": cache_state,
        "provenance": {
            "dependency_versions": {},
            "policy_digest": DIGEST,
            "cache": {"state": cache_state, "hit": cache_state == "hit"},
        },
    }


class CacheMetricSemanticsTests(unittest.TestCase):
    def test_unusable_cache_hits_are_effective_misses_not_duplicates(self):
        docs = [envelope(status=status, cache_state="hit")
                for status in ("partial", "timeout", "error", "cancelled")]
        metrics = aggregate(docs)

        self.assertEqual(metrics["cache_requests"], 4)
        self.assertEqual(metrics["cache_hits"], 0)
        self.assertEqual(metrics["cache_misses"], 4)
        self.assertEqual(metrics["cache_unusable_hits"], 4)
        self.assertEqual(metrics["duplicate_tool_calls"], 0)
        self.assertEqual(metrics["cache_hit_ratio"], 0.0)

    def test_repeated_real_misses_still_count_duplicate_computation(self):
        metrics = aggregate([envelope(cache_state="miss"), envelope(cache_state="miss")])

        self.assertEqual(metrics["cache_misses"], 2)
        self.assertEqual(metrics["cache_unusable_hits"], 0)
        self.assertEqual(metrics["duplicate_tool_calls"], 1)

    def test_successful_hit_remains_successful_reuse(self):
        metrics = aggregate([envelope(cache_state="miss"), envelope(cache_state="hit")])

        self.assertEqual(metrics["cache_requests"], 2)
        self.assertEqual(metrics["cache_hits"], 1)
        self.assertEqual(metrics["cache_misses"], 1)
        self.assertEqual(metrics["cache_unusable_hits"], 0)
        self.assertEqual(metrics["duplicate_tool_calls"], 0)
        self.assertEqual(metrics["cache_hit_ratio"], 0.5)

    def test_bypass_is_not_a_cache_request(self):
        metrics = aggregate([envelope(cache_state="bypass")])

        self.assertEqual(metrics["cache_requests"], 0)
        self.assertEqual(metrics["cache_unusable_hits"], 0)
        self.assertIsNone(metrics["cache_hit_ratio"])


if __name__ == "__main__":
    unittest.main()
