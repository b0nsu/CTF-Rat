import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.schema import validate, ValidationError
from ratlib.contracts import execute
from ratlib.metrics import aggregate, operation_fingerprint, first_primitive_pass_ts, process_trace_metrics
from ratlib.state_v2 import Stream

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

    def _provenance(self):
        return {
            "suite_digest": D,
            "corpora": ["private"],
            "agent": {"executable": "codex", "command_digest": D,
                      "model_id": "gpt-test", "reasoning_effort": "high"},
            "execution": {"timeout_seconds": 600, "observer_execve_trace": True},
            "environment": {"os": "linux", "arch": "x86_64", "runtime": "python-3.12"},
            "toolchain": {"ctf_rat_revision": "a" * 40, "schema_bundle": "v1"},
        }

    def test_valid_document_passes_without_provenance_for_backward_compatibility(self):
        validate(self._valid())

    def test_valid_optional_provenance_passes(self):
        doc = self._valid(); doc["provenance"] = self._provenance()
        validate(doc)

    def test_bad_provenance_digest_rejected(self):
        doc = self._valid(); doc["provenance"] = self._provenance(); doc["provenance"]["suite_digest"] = "sha256:bad"
        with self.assertRaises(ValidationError): validate(doc)

    def test_bad_provenance_timeout_rejected(self):
        doc = self._valid(); doc["provenance"] = self._provenance(); doc["provenance"]["execution"]["timeout_seconds"] = 0
        with self.assertRaises(ValidationError): validate(doc)

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

class ProcessTraceMetrics(unittest.TestCase):
    def test_counts_process_tools_duplicates_and_heavy_analyzers(self):
        with tempfile.TemporaryDirectory() as d:
            kit = os.path.join(d, "kit")
            chal = os.path.join(kit, "solve", "fixture")
            trace = os.path.join(d, "execve.log")
            lines = [
                f'100 execve("{kit}/bin/rat", ["rat", "route", "{chal}/chall"], 0x0) = 0',
                f'101 execve("{kit}/bin/rat-profile", ["rat-profile", "{chal}/chall", "--format", "json"], 0x0) = 0',
                f'102 execve("{kit}/bin/rat", ["rat", "route", "{chal}/chall"], 0x0) = 0',
                '103 execve("/opt/ghidra/support/analyzeHeadless", ["analyzeHeadless", "/tmp/proj", "p"], 0x0) = 0',
                f'104 execve("/usr/bin/python3", ["python3", "{kit}/solve/_template/rev/symsolve.py", "{chal}/chall", "--find", "0x401000"], 0x0) = 0',
                f'105 execve("{kit}/bin/revq", ["revq", "{chal}/chall"], 0x0) = -1 ENOENT (No such file or directory)',
            ]
            with open(trace, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            metrics = process_trace_metrics(trace, kit, chal)
            self.assertEqual(metrics["tool_calls"], 4)
            self.assertEqual(metrics["duplicate_tool_calls"], 1)
            self.assertEqual(metrics["ghidra_runs"], 1)
            self.assertEqual(metrics["symbolic_runs"], 1)
            self.assertEqual(metrics["tool_name_counts"].get("rat"), 2)
            self.assertEqual(metrics["tool_name_counts"].get("rat-profile"), 1)
            self.assertEqual(metrics["tool_name_counts"].get("symsolve.py"), 1)

    def test_missing_trace_is_unknown_not_zero(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(process_trace_metrics(os.path.join(d, "missing.log"), os.path.join(d, "kit")))

class Aggregate(unittest.TestCase):
    def test_bypass_and_unknown_states_are_not_cache_requests(self):
        bypass = envelope(cache_state="bypass")
        unknown = envelope()
        del unknown["cache_state"]
        unknown["provenance"]["cache"] = {"key": None, "hit": False,
                                            "source_invocation": None}
        metrics = aggregate([bypass, unknown])
        self.assertEqual(metrics["tool_calls"], 2)
        self.assertEqual(metrics["cache_requests"], 0)
        self.assertEqual(metrics["cache_hits"], 0)
        self.assertEqual(metrics["cache_misses"], 0)
        self.assertEqual(metrics["cache_unusable_hits"], 0)
        self.assertEqual(metrics["duplicate_tool_calls"], 0)
        self.assertIsNone(metrics["cache_hit_ratio"])

    def test_direct_subjects_use_distinct_cache_entries(self):
        with tempfile.TemporaryDirectory() as d:
            tool = os.path.join(d, "measure")
            for path, data in ((tool, b"#!/bin/sh\nprintf measured\n"),
                               (os.path.join(d, "a"), b"a"),
                               (os.path.join(d, "b"), b"b")):
                with open(path, "wb") as fh:
                    fh.write(data)
            os.chmod(tool, 0o755)
            a, b = os.path.join(d, "a"), os.path.join(d, "b")
            first = execute([tool], root=os.path.join(d, ".rat"), input_paths=[a, b], direct_subject=a)
            second = execute([tool], root=os.path.join(d, ".rat"), input_paths=[a, b], direct_subject=b)
            self.assertEqual(first["cache_state"], "miss")
            self.assertEqual(second["cache_state"], "miss")

    def test_command_arguments_use_distinct_cache_entries(self):
        with tempfile.TemporaryDirectory() as d:
            tool = os.path.join(d, "measure")
            with open(tool, "wb") as fh:
                fh.write(b"#!/bin/sh\nprintf '%s' \"$1\"\n")
            os.chmod(tool, 0o755)
            first = execute([tool, "first"], root=os.path.join(d, ".rat"))
            second = execute([tool, "second"], root=os.path.join(d, ".rat"))
            self.assertEqual(first["cache_state"], "miss")
            self.assertEqual(second["cache_state"], "miss")

    def test_duplicate_tool_calls_counts_repeated_fingerprint_misses(self):
        docs = [envelope(cache_state="miss"), envelope(cache_state="miss")]
        m = aggregate(docs)
        self.assertEqual(m["tool_calls"], 2)
        self.assertEqual(m["duplicate_tool_calls"], 1)
        self.assertEqual(m["cache_misses"], 2)
        self.assertEqual(m["cache_hits"], 0)
        self.assertEqual(m["cache_unusable_hits"], 0)

    def test_cache_hit_is_not_counted_as_duplicate_but_is_a_cache_request(self):
        docs = [envelope(cache_state="miss"), envelope(cache_state="hit")]
        m = aggregate(docs)
        self.assertEqual(m["duplicate_tool_calls"], 0)
        self.assertEqual(m["cache_hits"], 1)
        self.assertEqual(m["cache_requests"], 2)
        self.assertEqual(m["cache_unusable_hits"], 0)
        self.assertAlmostEqual(m["cache_hit_ratio"], 0.5)

    def test_unusable_cache_hits_remain_effective_misses_without_duplicates(self):
        docs = [envelope(status=status, cache_state="hit")
                for status in ("partial", "timeout", "error", "cancelled")]
        m = aggregate(docs)
        self.assertEqual(m["cache_requests"], 4)
        self.assertEqual(m["cache_hits"], 0)
        self.assertEqual(m["cache_misses"], 4)
        self.assertEqual(m["cache_unusable_hits"], 4)
        self.assertEqual(m["duplicate_tool_calls"], 0)
        self.assertEqual(m["cache_hit_ratio"], 0.0)

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

    def test_indexed_artifacts_backend_counts_default_empty(self):
        self.assertEqual(aggregate([envelope()])["indexed_artifacts_by_backend"], {})

    def test_indexed_artifacts_surface_tools_that_bypass_the_tool_result_store(self):
        # revq/decomp/pwngadget register in the shared cache index, not the
        # tool-result store metrics scans -- so with zero tool-result docs the
        # index backends are the only lineage signal they leave.
        from ratlib.cache import Cache, canonical_key
        from ratlib.metrics import index_backends
        with tempfile.TemporaryDirectory() as d:
            root = os.path.join(d, ".rat")
            c = Cache(root)
            c.put_entry(canonical_key(binary_sha256="sha256:" + "a" * 64, tool_name="revq",
                        tool_version="2", params={}, dep_versions={}), backend="revq_json", path="/tmp/x.revq.json")
            c.put_entry(canonical_key(binary_sha256="sha256:" + "a" * 64, tool_name="pwngadget",
                        tool_version="1", params={"q": "ret"}, dep_versions={}), backend="pwngadget", path="/tmp/g.json")
            m = aggregate([], index_backend_counts=index_backends(root))
            self.assertEqual(m["tool_calls"], 0)  # nothing in the tool-result store
            self.assertEqual(m["indexed_artifacts_by_backend"].get("revq_json"), 1)
            self.assertEqual(m["indexed_artifacts_by_backend"].get("pwngadget"), 1)

class FirstPrimitivePassTs(unittest.TestCase):
    """Once a v2 stream exists it is authoritative: a legacy PASS must never
    leak into v2 time-to-flag telemetry (the legacy `state primitive ... pass`
    command is itself rejected by bin/state, so trusting it here would let a
    rejected write resurface as a solved timestamp)."""

    def _write_legacy_pass(self, state_dir, ts):
        with open(os.path.join(state_dir, "STATE.jsonl"), "w", encoding="utf-8") as f:
            f.write(json.dumps({"t": "primitive", "status": "pass", "ts": ts}) + "\n")

    def test_legacy_pass_used_when_no_v2_stream(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_legacy_pass(d, 4242)
            self.assertEqual(first_primitive_pass_ts(d), 4242)

    def test_v2_stream_without_typed_pass_suppresses_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_legacy_pass(d, 4242)
            Stream(d).append("hypothesis.recorded", {"hypothesis_id": "h1"})
            self.assertIsNone(first_primitive_pass_ts(d))

if __name__ == "__main__":
    unittest.main()
