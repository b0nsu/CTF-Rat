import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.metrics import aggregate

D = "sha256:" + "a" * 64


def invocation(tool_name, invocation_id):
    return {
        "schema": "rat.tool-result/v1",
        "tool": {"name": tool_name, "version": "1", "build_digest": D},
        "run_id": invocation_id,
        "invocation_id": invocation_id,
        "status": "ok",
        "started_at": "2026-08-29T00:00:00Z",
        "finished_at": "2026-08-29T00:00:01Z",
        "duration_ms": 1,
        "inputs": [],
        "parameters": {},
        "summary": {},
        "artifacts": [],
        "findings": [],
        "diagnostics": [],
        "exit": {"code": 0, "signal": None, "timed_out": False, "cancelled": False},
        "provenance": {
            "platform": {},
            "dependency_versions": {},
            "policy_digest": D,
            "cache": {"state": "miss", "key": D},
        },
        "cache_state": "miss",
    }


class SessionMetricObservabilityTruthTests(unittest.TestCase):
    def test_decomp_invocation_is_not_promoted_to_function_count_or_ghidra_run(self):
        metrics = aggregate([
            invocation("decomp", "invoke_decomp"),
            invocation("revq", "invoke_revq"),
        ])

        self.assertEqual(metrics["decomp_invocations"], 1)
        self.assertEqual(metrics["revq_runs"], 1)
        self.assertIsNone(metrics["functions_decompiled"])
        self.assertIsNone(metrics["ghidra_runs"])

    def test_no_semantic_invocations_still_leave_stronger_work_metrics_unknown(self):
        metrics = aggregate([])
        self.assertEqual(metrics["decomp_invocations"], 0)
        self.assertIsNone(metrics["functions_decompiled"])
        self.assertIsNone(metrics["ghidra_runs"])


if __name__ == "__main__":
    unittest.main()
