#!/usr/bin/env python3
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from ratlib.benchmark_report import aggregate
from ratlib.telemetry import begin, finish, record_cache, record_model, record_tool


class BenchmarkReportTests(unittest.TestCase):
    def _run(self, root, run_id, ablation, attempt, *, verified, context, input_tokens,
             duplicate=False, cache_hit=False, eligible=True, status="completed"):
        chall = os.path.join(root, "chall")
        if not os.path.exists(chall):
            with open(chall, "wb") as f:
                f.write(b"fixture")
        begin(root, run_id=run_id, ablation_id=ablation, challenge_id="babyrev",
              attempt=attempt, eligible=eligible, model="model-x")
        record_model(input_tokens=input_tokens, output_tokens=100, context_tokens=context,
                     duration_ms=20, root=root)
        record_tool(["revq", "./chall", "--interesting"], duration_ms=10, exit_code=0,
                    cwd=root, root=root)
        if duplicate:
            record_tool(["revq", "chall", "--interesting"], duration_ms=11, exit_code=0,
                        cwd=root, root=root)
        record_cache(tool="revq", key="sha256:" + ("a" if cache_hit else "b") * 64,
                     hit=cache_hit, root=root)
        finish(root, status=status,
               outcome="verified" if verified else ("unknown" if status == "infra-failure" else "failed"),
               verified=verified, flag_found=verified)

    def test_aggregate_reports_solve_rate_medians_duplicates_and_cache(self):
        with tempfile.TemporaryDirectory() as d:
            self._run(d, "a0-1", "A0", 1, verified=True, context=100, input_tokens=1000,
                      duplicate=True, cache_hit=False)
            self._run(d, "a0-2", "A0", 2, verified=False, context=200, input_tokens=2000,
                      cache_hit=True)
            self._run(d, "a0-3", "A0", 3, verified=True, context=300, input_tokens=3000,
                      cache_hit=True)
            report = aggregate(d, challenge_id="babyrev")
            self.assertEqual(len(report["groups"]), 1)
            group = report["groups"][0]
            self.assertEqual(group["scored_runs"], 3)
            self.assertEqual(group["verified_runs"], 2)
            self.assertAlmostEqual(group["verified_solve_rate"], 2 / 3)
            self.assertTrue(group["enough_repeats"])
            self.assertEqual(group["median"]["peak_context_tokens"], 200)
            self.assertEqual(group["median"]["input_tokens"], 2000)
            self.assertEqual(group["duplicate_tool_calls_total"], 1)
            self.assertEqual(group["structured_cache"]["reads"], 3)
            self.assertEqual(group["structured_cache"]["hits"], 2)
            self.assertAlmostEqual(group["structured_cache"]["hit_ratio"], 2 / 3)

    def test_infra_and_ineligible_runs_do_not_pollute_default_denominator(self):
        with tempfile.TemporaryDirectory() as d:
            self._run(d, "a1-good", "A1", 1, verified=True, context=100, input_tokens=1000)
            self._run(d, "a1-infra", "A1", 2, verified=False, context=999, input_tokens=9999,
                      status="infra-failure")
            self._run(d, "a1-ineligible", "A1", 3, verified=False, context=999, input_tokens=9999,
                      eligible=False)
            group = aggregate(d, challenge_id="babyrev")["groups"][0]
            self.assertEqual(group["selected_runs"], 2)
            self.assertEqual(group["scored_runs"], 1)
            self.assertEqual(group["verified_runs"], 1)
            self.assertEqual(group["verified_solve_rate"], 1.0)
            self.assertEqual(group["infra_failures"], 1)
            self.assertEqual(group["excluded_ineligible"], 1)
            self.assertFalse(group["enough_repeats"])
            self.assertEqual(group["median"]["peak_context_tokens"], 100)

    def test_active_run_is_ignored_not_scored_as_partial_failure(self):
        with tempfile.TemporaryDirectory() as d:
            self._run(d, "done", "A0", 1, verified=True, context=100, input_tokens=1000)
            begin(d, run_id="active-now", ablation_id="A0", challenge_id="babyrev", attempt=2)
            report = aggregate(d, challenge_id="babyrev", min_runs=1)
            group = report["groups"][0]
            self.assertEqual(group["scored_runs"], 1)
            self.assertEqual(group["verified_solve_rate"], 1.0)
            self.assertTrue(any(x["run_id"] == "active-now" for x in report["ignored_runs"]))


if __name__ == "__main__":
    unittest.main()
