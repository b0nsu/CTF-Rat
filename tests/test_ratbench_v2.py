import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(ROOT, "bin")
sys.path.insert(0, BIN)


def _load_ratbench():
    loader = importlib.machinery.SourceFileLoader("_ratbench_v2", os.path.join(BIN, "ratbench"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


RATBENCH = _load_ratbench()

ENTRY = {
    "id": "fixture-01",
    "track": "pwn",
    "difficulty": 1,
    "expected_route": "pwn-stack",
    "verify": {"kind": "flag-regex"},
}


class ModeBV2RecordTests(unittest.TestCase):
    def test_verified_record_uses_canonical_outcome_and_measured_latencies(self):
        events = [
            {"type": "governor.checked", "at": "2026-08-29T00:00:01.250+00:00",
             "payload": {"action": "query:func"}},
            {"type": "hypothesis.recorded", "at": "2026-08-29T00:00:02.500+00:00", "payload": {}},
            {"type": "verification.recorded", "at": "2026-08-29T00:00:05.750+00:00",
             "payload": {"verification_id": "verify_1"}},
        ]
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:06+00:00",
            agent_rc=0, flag_claimed=True,
            completion={"verified": True, "reason": "verified", "verification_id": "verify_1"},
            events=events, primitive_pass_at=1787961603, artifact_count=7,
            process_metrics={"tool_calls": 4, "duplicate_tool_calls": 1,
                             "ghidra_runs": 1, "symbolic_runs": 1},
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v2")
        self.assertEqual(doc["schema"], "rat.benchmark-result/v2")
        self.assertEqual(doc["outcome"], "verified")
        self.assertTrue(doc["metrics"]["correctness"]["verified_solve"])
        self.assertFalse(doc["metrics"]["correctness"]["false_solved"])
        self.assertEqual(doc["metrics"]["latency"]["time_to_first_query_ms"], 1250)
        self.assertEqual(doc["metrics"]["latency"]["time_to_first_hypothesis_ms"], 2500)
        self.assertEqual(doc["metrics"]["latency"]["time_to_first_valid_primitive_ms"], 3000)
        self.assertEqual(doc["metrics"]["latency"]["time_to_verified_solve_ms"], 5750)
        self.assertEqual(doc["metrics"]["artifacts"]["artifact_count"], 7)
        self.assertIsNone(doc["metrics"]["context"]["input_tokens"])
        self.assertEqual(doc["metrics"]["tools"]["tool_calls"], 4)
        self.assertEqual(doc["metrics"]["tools"]["duplicate_tool_calls"], 1)
        self.assertEqual(doc["metrics"]["tools"]["ghidra_runs"], 1)
        self.assertEqual(doc["metrics"]["tools"]["symbolic_runs"], 1)
        self.assertIsNone(doc["metrics"]["tools"]["cfgfast_runs"])

    def test_flag_without_completion_is_only_solve_claimed(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A1",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:10+00:00",
            agent_rc=0, flag_claimed=True,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=1787961604, artifact_count=0,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v2")
        self.assertEqual(doc["outcome"], "solve-claimed")
        self.assertFalse(doc["metrics"]["correctness"]["verified_solve"])
        self.assertTrue(doc["metrics"]["correctness"]["false_solved"])
        self.assertIsNone(doc["metrics"]["latency"]["time_to_verified_solve_ms"])

    def test_timeout_without_verified_solve_is_censored(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A2",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:10:00+00:00",
            agent_rc=124, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v2")
        self.assertEqual(doc["status"], "timeout")
        self.assertEqual(doc["outcome"], "censored")
        self.assertFalse(doc["metrics"]["correctness"]["false_solved"])
        self.assertIsNone(doc["metrics"]["tools"]["tool_calls"])
        self.assertIsNone(doc["metrics"]["tools"]["duplicate_tool_calls"])

    def test_legacy_report_ignores_v2_companion(self):
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "T.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "schema": "rat.bench-result/v1", "run_id": "T", "mode": "B",
                    "id": "fixture-01", "difficulty": 1, "route_ok": False, "outcome": "fail"
                }) + "\n")
            with open(os.path.join(results, "T.benchmark-v2.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"schema": "rat.benchmark-result/v2", "benchmark_run_id": "T"}) + "\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None)), 0)
            leaderboard = open(os.path.join(d, "bench", "LEADERBOARD.md"), encoding="utf-8").read()
            self.assertIn("| T | B | 1 |", leaderboard)
            self.assertNotIn("| ? |", leaderboard)

    def test_v2_report_uses_only_eligible_rows_and_shows_metric_coverage(self):
        verified = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="T", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:06+00:00",
            agent_rc=0, flag_claimed=True,
            completion={"verified": True, "reason": "verified", "verification_id": "verify_1"},
            events=[{"type": "verification.recorded", "at": "2026-08-29T00:00:05+00:00",
                     "payload": {"verification_id": "verify_1"}}],
            primitive_pass_at=None, artifact_count=2,
            process_metrics={"tool_calls": 4, "duplicate_tool_calls": 1,
                             "ghidra_runs": 1, "symbolic_runs": 0},
        )
        failed = RATBENCH._mode_b_v2_record(
            {**ENTRY, "id": "fixture-02"}, run_id="T", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:08+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=1,
        )
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "T.benchmark-v2.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps(verified) + "\n")
                fh.write(json.dumps(failed) + "\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None, schema="v2")), 0)
            leaderboard = open(os.path.join(d, "bench", "LEADERBOARD.v2.md"), encoding="utf-8").read()
            self.assertIn("| T | A0 | 2 | 1 | 0 | 1 | 0 | 50.0% |", leaderboard)
            self.assertIn("5000ms (1/2)", leaderboard)
            self.assertIn("4 (1/2)", leaderboard)
            self.assertIn("1 (1/2)", leaderboard)
            self.assertIn("n/a (0/2)", leaderboard)

    def test_v2_report_rejects_malformed_rows_instead_of_biasing_results(self):
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "bad.benchmark-v2.jsonl"), "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None, schema="v2")), 3)
            self.assertFalse(os.path.exists(os.path.join(d, "bench", "LEADERBOARD.v2.md")))


if __name__ == "__main__":
    unittest.main()
