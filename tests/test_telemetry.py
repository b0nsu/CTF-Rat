import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.schema import validate, ValidationError
from ratlib.contracts import execute
from ratlib.metrics import aggregate, operation_fingerprint

D = "sha256:" + "a" * 64

def envelope(**overrides):
    doc = {
        "schema": "rat.tool-result/v1", "tool": {"name": "x", "version": "1", "build_digest": D},
        "run_id": "r", "invocation_id": "i" + str(id(overrides)), "status": "ok",
        "started_at": "2020-01-01T00:00:00Z", "finished_at": "2020-01-01T00:00:00Z", "duration_ms": 10,
        "inputs": [], "parameters": {}, "summary": {}, "artifacts": [], "findings": [], "diagnostics": [],
        "exit": {"code": 0, "signal": None, "timed_out": False, "cancelled": False},
        "provenance": {"platform": {}, "dependency_versions": {}, "policy_digest": D, "cache": {"key": "k", "hit": False, "source_invocation": None}},
        "tool_name": "x", "params_digest": "unindexed", "cache_state": "miss",
    }
    doc.update(overrides)
    return doc

class ToolResultSchema(unittest.TestCase):
    def test_optional_telemetry_fields_are_accepted(self):
        validate(envelope())

    def test_cache_state_must_be_known_enum(self):
        with self.assertRaises(ValidationError):
            validate(envelope(cache_state="stale"))

    def test_legacy_envelope_without_new_fields_still_validates(self):
        doc = envelope()
        del doc["tool_name"]; del doc["params_digest"]; del doc["cache_state"]
        validate(doc)

class BenchmarkResultV2Schema(unittest.TestCase):
    def _valid(self):
        return {
            "schema": "rat.benchmark-result/v2", "benchmark_run_id": "r1", "ablation_id": "A0",
            "challenge_id": "c1", "attempt": 1, "status": "completed", "eligible": True, "outcome": "verified",
            "started_at": "2026-08-23T00:00:00Z", "finished_at": "2026-08-23T00:01:00Z", "oracle": {}, "ground_truth": {},
            "metrics": {
                "correctness": {"verified_solve": True, "false_solved": False, "oracle_pass": True},
                "latency": {"time_to_first_query_ms": 1, "time_to_first_hypothesis_ms": 2, "time_to_first_valid_primitive_ms": 3, "time_to_verified_solve_ms": 4},
                "context": {"input_tokens": 1, "output_tokens": 2, "peak_context_tokens": 3, "tool_output_bytes": 4},
                "tools": {"tool_calls": 1, "duplicate_tool_calls": 0, "ghidra_runs": 0, "cfgfast_runs": 0, "symbolic_runs": 0, "subagent_count": 0},
                "cache": {"cache_requests": 1, "cache_hits": 0, "cache_hit_ratio": 0.0, "bytes_reused": 0, "cold_warm": "cold"},
                "reasoning": {"hypotheses_created": 0, "hypotheses_refuted": 0, "pivot_count": 0, "deep_escalations": 0},
                "artifacts": {"functions_decompiled": 0, "raw_output_size": 0, "compressed_output_size": 0, "artifact_count": 0},
            },
        }

    def test_valid_document_passes(self):
        validate(self._valid())

    def test_missing_metric_group_rejected(self):
        doc = self._valid(); del doc["metrics"]["cache"]
        with self.assertRaises(ValidationError): validate(doc)

    def test_bad_cold_warm_rejected(self):
        doc = self._valid(); doc["metrics"]["cache"]["cold_warm"] = "lukewarm"
        with self.assertRaises(ValidationError): validate(doc)

    def test_bad_cache_hit_ratio_rejected(self):
        doc = self._valid(); doc["metrics"]["cache"]["cache_hit_ratio"] = 1.5
        with self.assertRaises(ValidationError): validate(doc)

class OperationFingerprint(unittest.TestCase):
    def test_identical_inputs_produce_identical_fingerprint(self):
        self.assertEqual(operation_fingerprint(envelope()), operation_fingerprint(envelope()))

    def test_different_parameters_change_fingerprint(self):
        self.assertNotEqual(operation_fingerprint(envelope(parameters={"a": 1})), operation_fingerprint(envelope(parameters={"a": 2})))

class Aggregate(unittest.TestCase):
    def test_duplicate_tool_calls_counts_repeated_fingerprint_misses(self):
        docs = [envelope(cache_state="miss"), envelope(cache_state="miss")]
        m = aggregate(docs)
        self.assertEqual(m["tool_calls"], 2)
        self.assertEqual(m["duplicate_tool_calls"], 1)
        self.assertEqual(m["cache_misses"], 2)
        self.assertEqual(m["cache_hits"], 0)

    def test_cache_hit_is_not_counted_as_duplicate_but_is_a_cache_request(self):
        docs = [envelope(cache_state="miss"), envelope(cache_state="hit")]
        m = aggregate(docs)
        self.assertEqual(m["duplicate_tool_calls"], 0)
        self.assertEqual(m["cache_hits"], 1)
        self.assertEqual(m["cache_requests"], 2)
        self.assertAlmostEqual(m["cache_hit_ratio"], 0.5)

    def test_timeout_or_partial_run_never_counts_as_cache_hit(self):
        docs = [envelope(status="timeout", cache_state="hit"), envelope(status="partial", cache_state="hit")]
        m = aggregate(docs)
        self.assertEqual(m["cache_hits"], 0)
        self.assertEqual(m["cache_misses"], 2)

    def test_truncated_run_is_never_a_cache_hit_via_contracts_execute(self):
        with tempfile.TemporaryDirectory() as d:
            first = execute(["/bin/echo", "hello world telemetry"], root=d, timeout=5)
            self.assertEqual(first["cache_state"], "miss")
            second = execute(["/bin/echo", "hello world telemetry"], root=d, timeout=5)
            self.assertEqual(second["cache_state"], "hit")
            self.assertNotEqual(second["invocation_id"], first["invocation_id"])
            self.assertTrue(second["provenance"]["cache"]["hit"])
            self.assertEqual(second["provenance"]["cache"]["source_invocation"], first["invocation_id"])
            m = aggregate([first, second])
            self.assertEqual(m["duplicate_tool_calls"], 0)
            self.assertEqual(m["cache_hits"], 1)
            self.assertEqual(m["cache_requests"], 2)

    def test_time_to_flag_sec_is_null_without_guard_or_pass_timestamps(self):
        self.assertIsNone(aggregate([envelope()])["time_to_flag_sec"])

    def test_time_to_flag_sec_is_elapsed_seconds_between_guard_begin_and_verify_pass(self):
        m = aggregate([envelope()], guard_started_at=1000, verify_pass_at=1090)
        self.assertEqual(m["time_to_flag_sec"], 90)

if __name__ == "__main__":
    unittest.main()
