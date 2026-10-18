import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.metrics import aggregate
from ratlib.schema import validate


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

    def test_no_requests_reports_none_ratio_not_zero(self):
        # R2-8: with nothing measured, the ratio is null (unknown), never 0 (which
        # would read as "0% reuse" and be mistaken for a measurement).
        metrics = aggregate([])
        self.assertEqual(metrics["cache_requests"], 0)
        self.assertIsNone(metrics["cache_hit_ratio"])

    def test_cache_stats_schema_does_not_claim_session_hit_miss(self):
        # R2-8: `rat cache stats` is index-level only; it must not expose
        # uninstrumented session hit/miss/ratio fields (those live in rat-metrics).
        doc = {"schema": "rat.cache-stats/v1", "store": "/tmp/x", "total_entries": 0,
               "by_backend": {}, "oldest_produced_at": None, "newest_produced_at": None}
        validate(doc, "rat.cache-stats/v1")  # baseline is valid
        for field in ("cache_hits", "cache_misses", "cache_hit_ratio", "cache_requests"):
            with self.subTest(field=field):
                bad = dict(doc)
                bad[field] = 0
                with self.assertRaises(Exception):
                    validate(bad, "rat.cache-stats/v1")


if __name__ == "__main__":
    unittest.main()
