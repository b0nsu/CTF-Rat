import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tests.test_ratbench_v2 import RATBENCH, ENTRY, require_mode_b_sandbox
from tests.test_telemetry import envelope
from ratlib.artifact import put_bytes
from ratlib.metrics import aggregate, benchmark_envelope_observations
from ratlib.schema import validate, ValidationError


def store(root, doc):
    put_bytes(json.dumps(doc).encode(), kind="tool-result", media_type="application/json",
              logical_name="result.json", root=str(root))


def mixed_store(root):
    store(root, envelope(invocation_id="normal", summary={"stdout_bytes": 3, "stderr_bytes": 2}))
    text = envelope(invocation_id="text", summary="valid human summary", cache_state="hit")
    validate(text)
    store(root, text)
    for doc in ([], "not an envelope", {"schema": "rat.tool-result/v1", "tool": []},
                envelope(provenance="bad"), envelope(inputs=["bad"]),
                envelope(provenance={"cache": "bad"}), envelope(tool={"name": []}),
                envelope(inputs=[{"digest": []}]), envelope(parameters=[]),
                envelope(duration_ms="bad")):
        store(root, doc)
    metadata = Path(root) / "metadata" / "sha256" / "zz"
    metadata.mkdir(parents=True)
    for index, raw in enumerate(('[]', 'null', '{bad', '{"kind":"tool-result","digest":4}')):
        (metadata / (str(index) + ".json")).write_text(raw)


class ObservationBoundaries(unittest.TestCase):
    def test_only_corrupt_artifacts_do_not_become_zero_observations(self):
        with tempfile.TemporaryDirectory() as root:
            store(root, [])
            store(root, envelope(provenance={"cache": []}))
            self.assertIsNone(benchmark_envelope_observations(root))

    def test_exit_124_without_timeout_is_a_completed_failure(self):
        row = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="test", ablation_id="A0",
            started_at="2026-09-22T00:00:00Z", finished_at="2026-09-22T00:00:01Z",
            agent_rc=124, flag_claimed=False, completion={"verified": False},
            events=[], primitive_pass_at=None, artifact_count=0)
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["outcome"], "failed")
        self.assertEqual(row["oracle"]["failure_class"], "agent-nonzero-exit")

    def test_timeout_preserves_verified_and_claim_priorities(self):
        for verified, claimed, outcome, failure in (
                (True, True, "verified", None),
                (False, True, "solve-claimed", "agent-timeout")):
            with self.subTest(verified=verified):
                row = RATBENCH._mode_b_v2_record(
                    ENTRY, run_id="test", ablation_id="A0",
                    started_at="2026-09-22T00:00:00Z", finished_at="2026-09-22T00:00:01Z",
                    agent_rc=124, timed_out=True, flag_claimed=claimed,
                    completion={"verified": verified}, events=[],
                    primitive_pass_at=None, artifact_count=0)
                self.assertEqual(row["status"], "timeout")
                self.assertEqual(row["outcome"], outcome)
                self.assertEqual(row["oracle"]["failure_class"], failure)

    def test_mixed_store_keeps_valid_string_summary_and_unknown_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            mixed_store(root)
            observed = benchmark_envelope_observations(root)
            self.assertEqual(observed["envelope_count"], 2)
            self.assertEqual(observed["cache_requests"], 2)
            self.assertEqual(observed["cache_hits"], 1)
            self.assertIsNone(observed["captured_stdout_stderr_bytes"])

    def test_non_object_summaries_are_valid_but_have_unknown_capture_size(self):
        for summary in ("text", [], 42, None, False):
            with self.subTest(summary=summary), tempfile.TemporaryDirectory() as root:
                doc = envelope(summary=summary)
                validate(doc)
                store(root, doc)
                self.assertIsNone(benchmark_envelope_observations(root)["captured_stdout_stderr_bytes"])

    def test_canonical_name_and_legacy_fallback_agree_across_aggregates(self):
        docs = [envelope(invocation_id=str(i)) for i in range(4)]
        del docs[1]["tool_name"]
        validate(docs[0])
        validate(docs[1])
        del docs[2]["tool"]  # Historical telemetry projection, not a current envelope.
        docs[3]["tool_name"] = "decomp"
        with self.assertRaises(ValidationError):
            validate(docs[3])
        with tempfile.TemporaryDirectory() as root:
            for doc in docs:
                store(root, doc)
            observed = benchmark_envelope_observations(root)
            self.assertEqual(set(observed["by_tool"]), {"x"})
            for field in ("envelope_count", "cache_requests", "cache_hits", "cache_unusable_hits"):
                self.assertEqual(observed[field], sum(row[field] for row in observed["by_tool"].values()))
            self.assertEqual(aggregate(docs)["decomp_invocations"], 0)

    def test_actual_process_exit_and_timeout_save_results_with_mixed_artifacts(self):
        require_mode_b_sandbox()
        for code, timeout, expected in (("raise SystemExit(124)", 5, ("completed", "failed", "agent-nonzero-exit")),
                                        ("import time; time.sleep(5)", 0.1, ("timeout", "censored", "agent-timeout"))):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as scratch, tempfile.TemporaryDirectory() as runtime:
                chal = Path(runtime) / "chal"
                chal.mkdir()
                mixed_store(chal / ".rat")
                args = SimpleNamespace(agent=shlex.join([sys.executable, "-c", code]),
                                       run_id="boundary", ablation="A0", timeout=timeout,
                                       model_id="test", reasoning_effort="none")
                with mock.patch.object(RATBENCH, "ctf_home", return_value=scratch), \
                     mock.patch.object(RATBENCH, "_select_entries", return_value=[ENTRY]), \
                     mock.patch.object(RATBENCH, "_prepare_eval_workspace", return_value=(runtime, str(chal), None)), \
                     mock.patch.object(RATBENCH, "_benchmark_provenance", return_value=None), \
                     mock.patch.object(RATBENCH, "_strace_usable", return_value=False):
                    self.assertEqual(RATBENCH.cmd_eval(args), 0)
                path = Path(scratch) / "bench/results/boundary.benchmark-v3.jsonl"
                row = json.loads(path.read_text())
                validate(row)
                self.assertEqual((row["status"], row["outcome"], row["oracle"]["failure_class"]), expected)
                self.assertEqual(row["observations"]["tool_result_envelopes"]["envelope_count"], 2)
                self.assertIsNone(row["observations"]["tool_result_envelopes"]["captured_stdout_stderr_bytes"])
