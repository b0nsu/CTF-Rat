import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOL = ROOT / "benchmarks" / "tools" / "telemetry_summary.py"


def row(challenge, outcome="verified", metrics=None, attempt=1):
    return {
        "schema": "rat.benchmark-result/v1",
        "benchmark_run_id": "bench_test",
        "ablation_id": "A0",
        "corpus_digest": "sha256:" + "0" * 64,
        "challenge_id": challenge,
        "attempt": attempt,
        "status": "completed",
        "eligible": True,
        "outcome": outcome,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "metrics": metrics or {},
        "oracle": {"passed": outcome == "verified", "provenance_valid": True},
        "ground_truth": {"required_claims": ["fact"], "active_claims": ["fact"]},
    }


class BenchmarkTelemetry(unittest.TestCase):
    def test_summarizes_new_and_legacy_metrics(self):
        rows = [
            row("a", metrics={
                "time_to_flag_seconds": 4.0,
                "first_primitive_seconds": 1.0,
                "input_tokens": 100,
                "output_tokens": 40,
                "peak_context_tokens": 800,
                "cache_creation_tokens": 10,
                "cache_read_tokens": 50,
                "tool_calls": 8,
                "duplicate_tool_calls": {"strings": 2, "revq": 1},
                "cacheable_invocations": 6,
                "cache_hits": 4,
                "cache_lookups": 5,
            }),
            row("b", outcome="failed", metrics={
                "tts_seconds": 8.0,
                "tokens": 200,
                "duplicate_calls": 1,
                "cacheable_invocations": 4,
                "cache_hits": 1,
                "cache_lookups": 3,
            }),
            row("a-retry", metrics={"tts_seconds": 1.0, "tokens": 9999}, attempt=2),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "challenge-results.jsonl"
            path.write_text("".join(json.dumps(x) + "\n" for x in rows))
            proc = subprocess.run([sys.executable, str(TOOL), str(path)], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        metrics = out["metrics"]
        self.assertEqual(out["result_count"], 2)
        self.assertEqual(metrics["verified_solve_rate"], 0.5)
        self.assertEqual(metrics["median_time_to_flag_seconds"], 6.0)
        self.assertEqual(metrics["total_tokens"], 340)
        self.assertEqual(metrics["median_peak_context_tokens"], 800)
        self.assertEqual(metrics["duplicate_tool_calls"], 4)
        self.assertEqual(metrics["duplicate_tool_call_breakdown"], {"revq": 1, "strings": 2})
        self.assertAlmostEqual(metrics["duplicate_tool_call_rate"], 0.4)
        self.assertAlmostEqual(metrics["cache_hit_ratio"], 5 / 8)

    def test_rejects_negative_telemetry(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "challenge-results.jsonl"
            path.write_text(json.dumps(row("a", metrics={"tool_calls": -1})) + "\n")
            proc = subprocess.run([sys.executable, str(TOOL), str(path)], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 5)
        self.assertIn("tool_calls must be non-negative", proc.stderr)


if __name__ == "__main__":
    unittest.main()
