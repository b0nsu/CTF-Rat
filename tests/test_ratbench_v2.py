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
    "difficulty": 1,
    "expected": {"leads": ["stack-overwrite"], "action": "rat query pwn"},
    "corpus": "private",
    "capabilities": ["stack-overflow"],
    "redistributable": False,
    "verify": {"kind": "flag-regex"},
}


def _suite_entry(entry_id, corpus):
    return {
        "id": entry_id,
        "expected": {"leads": ["stack-overwrite"], "action": "rat query pwn"},
        "difficulty": 1,
        "corpus": corpus,
        "capabilities": ["stack-overflow"],
        "redistributable": corpus != "private",
        "dir": "bench/artifacts/stack-basic-01",
        "source": "src.c",
        "route_fixture": "route.json",
        "verify": {"kind": "flag-regex", "pattern": "FLAG\\{.+\\}"},
        "env": {"needs_libc": False},
    }


def _provenance(*, timeout=600, command_digest=None):
    digest = command_digest or ("sha256:" + "a" * 64)
    return {
        "suite_digest": "sha256:" + "b" * 64,
        "corpora": ["private"],
        "agent": {"executable": "codex", "command_digest": digest,
                  "model_id": "gpt-test", "reasoning_effort": "high"},
        "execution": {"timeout_seconds": timeout, "observer_execve_trace": True},
        "environment": {"os": "linux", "arch": "x86_64", "runtime": "python-3.12"},
        "toolchain": {"ctf_rat_revision": "c" * 40, "schema_bundle": "v1"},
    }


def _routing(**overrides):
    doc = {
        "first_dimensions": {"vulnerability_surfaces": ["stack-overwrite-candidate"], "program_shapes": [], "obstacles": [], "constraints": []},
        "first_action": {"action": "rat query pwn", "target": "x", "evidence": ["overflow-imports"], "rule": "x"},
        "first_commitment": "provisional",
        "route_assessment_count": 2,
        "decision_revision_count": 1,
        "first_skill": "pwn-stack",
    }
    doc.update(overrides)
    return doc


class CorpusGateTests(unittest.TestCase):
    def _write_suite(self, directory, entries):
        path = os.path.join(directory, "suite.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"schema": "rat.bench-suite/v2", "entries": entries}, fh)
        return path

    def test_select_entries_projects_one_corpus_before_execution(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write_suite(d, [
                _suite_entry("synthetic-01", "synthetic"),
                _suite_entry("heldout-01", "private"),
            ])
            entries = RATBENCH._select_entries(SimpleNamespace(suite=path, corpus="private", id=None))
            self.assertEqual([entry["id"] for entry in entries], ["heldout-01"])

    def test_select_entries_fails_closed_for_empty_requested_corpus(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write_suite(d, [_suite_entry("synthetic-01", "synthetic")])
            with self.assertRaisesRegex(RATBENCH.SuiteValidationError, "no entries for corpus: private"):
                RATBENCH._select_entries(SimpleNamespace(suite=path, corpus="private", id=None))

    def test_cmd_run_rejects_malformed_suite_before_route_or_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{bad")
            args = SimpleNamespace(suite=path, corpus=None, id=None, run_id="T")
            with mock.patch.object(RATBENCH, "_check_route") as route, mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_run(args), 3)
            route.assert_not_called()

    def test_id_is_scoped_to_selected_corpus(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._write_suite(d, [
                _suite_entry("synthetic-01", "synthetic"),
                _suite_entry("heldout-01", "private"),
            ])
            with self.assertRaisesRegex(LookupError, "no entry synthetic-01"):
                RATBENCH._select_entries(SimpleNamespace(
                    suite=path, corpus="private", id="synthetic-01"))



class ModeBLocalSmokeTests(unittest.TestCase):
    def test_flag_paths_are_rejected(self):
        for path in ("flag", "flag.txt", "assets/secret.flag"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "flag file"):
                RATBENCH._runtime_fixture_relpath(path)

    def test_agent_wrapper_uses_platform_filesystem_sandbox(self):
        with mock.patch.object(RATBENCH, "ctf_home", return_value="/operator/ctf-rat"), \
             mock.patch.object(RATBENCH, "_have", return_value=True), \
             mock.patch.object(RATBENCH.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            with mock.patch.object(RATBENCH.sys, "platform", "darwin"):
                RATBENCH._run_agent("echo ready", cwd="/tmp/kit/solve/case", env={}, timeout=5)
                argv = run.call_args.args[0]
                self.assertEqual(argv[:2], ["sandbox-exec", "-p"])
                self.assertIn("/operator/ctf-rat", argv[2])
                self.assertEqual(argv[-3:], ["/bin/sh", "-c", "echo ready"])
            with mock.patch.object(RATBENCH.sys, "platform", "linux"):
                RATBENCH._run_agent("echo ready", cwd="/tmp/kit/solve/case", env={}, timeout=5)
                argv = run.call_args.args[0]
                self.assertEqual(argv[0], "bwrap")
                self.assertEqual(argv[argv.index("--tmpfs") + 1], "/operator/ctf-rat")
                self.assertEqual(argv[-3:], ["/bin/sh", "-c", "echo ready"])

    @unittest.skipUnless(os.name == "posix" and os.path.isfile(sys.executable),
                         "local python interpreter required")
    def test_real_mode_b_exec_without_completion_remains_unverified(self):
        # Execute the actual Mode B workspace/export + external process path.
        # This is a negative-gate smoke, NOT a model-solving benchmark.
        with tempfile.TemporaryDirectory() as scratch:
            run_id = "B-smoke-" + os.path.basename(scratch)
            result_dir = os.path.join(ROOT, "bench", "results")
            legacy = os.path.join(result_dir, run_id + ".jsonl")
            canonical = os.path.join(result_dir, run_id + ".benchmark-v3.jsonl")
            args = SimpleNamespace(
                agent=sys.executable + " -c 'print(\"FLAG{smoke-no-proof}\")' {dir}",
                suite=None, corpus="synthetic", id="stack-basic-01",
                run_id=run_id, ablation="A0", timeout=20,
                model_id="python-negative-smoke", reasoning_effort="none",
            )
            try:
                with mock.patch.object(RATBENCH, "_strace_usable", return_value=False):
                    self.assertEqual(RATBENCH.cmd_eval(args), 0)
                with open(canonical, encoding="utf-8") as fh:
                    row = json.loads(fh.readline())
                RATBENCH.validate(row, "rat.benchmark-result/v3")
                self.assertEqual(row["outcome"], "solve-claimed")
                self.assertEqual(row["oracle"]["failure_class"], "claim-without-completion")
                self.assertFalse(row["metrics"]["correctness"]["verified_solve"])
                self.assertTrue(row["metrics"]["correctness"]["false_solved"])
                self.assertIsNone(row["metrics"]["context"]["input_tokens"])
                self.assertIsNone(row["metrics"]["tools"]["tool_calls"])
            finally:
                for filename in (legacy, canonical):
                    if os.path.exists(filename):
                        os.unlink(filename)


class BenchmarkProvenanceTests(unittest.TestCase):
    def test_provenance_hashes_exact_execution_set_and_agent_template(self):
        entries = [_suite_entry("heldout-01", "private")]
        args = SimpleNamespace(
            agent="codex --model gpt-test solve {dir}", timeout=321,
            model_id="gpt-test", reasoning_effort="high",
        )
        environment = {"os": "linux", "arch": "x86_64", "runtime": "python-3.12"}
        toolchain = {"ctf_rat_revision": "d" * 40, "schema_bundle": "v1"}
        with mock.patch.object(RATBENCH, "environment_identity", return_value=environment), \
             mock.patch.object(RATBENCH, "toolchain_identity", return_value=toolchain):
            doc = RATBENCH._benchmark_provenance(args, "codex", entries, True)
        self.assertEqual(doc["suite_digest"], RATBENCH.suite_digest(RATBENCH._selected_suite_doc(entries)))
        self.assertEqual(doc["corpora"], ["private"])
        self.assertEqual(doc["agent"]["executable"], "codex")
        self.assertEqual(doc["agent"]["command_digest"], RATBENCH._command_digest(args.agent))
        self.assertEqual(doc["agent"]["model_id"], "gpt-test")
        self.assertEqual(doc["agent"]["reasoning_effort"], "high")
        self.assertEqual(doc["execution"], {"timeout_seconds": 321, "observer_execve_trace": True})
        self.assertEqual(doc["environment"], environment)
        self.assertEqual(doc["toolchain"], toolchain)
        RATBENCH.validate({
            **RATBENCH._mode_b_v2_record(
                ENTRY, run_id="B-test", ablation_id="A0",
                started_at="2026-08-29T00:00:00+00:00", finished_at="2026-08-29T00:00:01+00:00",
                agent_rc=1, flag_claimed=False,
                completion={"verified": False, "reason": "no-active-verification"},
                events=[], primitive_pass_at=None, artifact_count=0, provenance=doc,
            )
        }, "rat.benchmark-result/v3")


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
            provenance=_provenance(), routing_metrics=_routing(),
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertEqual(doc["schema"], "rat.benchmark-result/v3")
        self.assertEqual(doc["outcome"], "verified")
        self.assertTrue(doc["metrics"]["correctness"]["verified_solve"])
        self.assertFalse(doc["metrics"]["correctness"]["false_solved"])
        self.assertIsNone(doc["oracle"]["failure_class"])
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
        self.assertEqual(doc["ground_truth"]["corpus"], "private")
        self.assertEqual(doc["ground_truth"]["capabilities"], ["stack-overflow"])
        self.assertFalse(doc["ground_truth"]["redistributable"])
        self.assertEqual(doc["provenance"], _provenance())
        self.assertEqual(doc["routing"], _routing())

    def test_denied_symbolic_bypass_is_telemetried_as_tooling_gap(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-denied-symbolic", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=0, flag_claimed=True,
            completion={"verified": False, "reason": "unsanctioned-symbolic-engine"},
            events=[], primitive_pass_at=None, artifact_count=0,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertEqual(doc["outcome"], "solve-claimed")
        self.assertEqual(doc["oracle"]["failure_class"], "tooling-gap:symsolve-bypass")

    def test_envelope_observations_are_scoped_and_do_not_invent_run_wide_metrics(self):
        observed = {
            "scope": "tool-result-envelopes-only", "envelope_count": 3,
            "cache_requests": 2, "cache_hits": 1, "cache_unusable_hits": 0,
            "cache_hit_ratio": 0.5, "captured_stdout_stderr_bytes": 21,
        }
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-scoped", ablation_id="A1",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=3,
            envelope_observations=observed,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertEqual(doc["observations"]["tool_result_envelopes"], observed)
        self.assertIsNone(doc["metrics"]["cache"]["cache_requests"])
        self.assertIsNone(doc["metrics"]["cache"]["cache_hits"])
        self.assertIsNone(doc["metrics"]["cache"]["cache_hit_ratio"])
        self.assertIsNone(doc["metrics"]["context"]["tool_output_bytes"])
        self.assertIsNone(doc["metrics"]["context"]["input_tokens"])

    def test_envelope_observations_reject_incoherent_counts_and_ratios(self):
        good = {
            "scope": "tool-result-envelopes-only", "envelope_count": 2,
            "cache_requests": 2, "cache_hits": 1, "cache_unusable_hits": 0,
            "cache_hit_ratio": 0.5, "captured_stdout_stderr_bytes": 5,
        }
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-scoped", ablation_id="A1",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=2,
            envelope_observations=good,
        )
        for changes in ({"cache_hits": 3}, {"cache_hit_ratio": 0.0},
                        {"cache_hit_ratio": float("nan")},
                        {"cache_hit_ratio": float("inf")},
                        {"cache_hit_ratio": float("-inf")},
                        {"captured_stdout_stderr_bytes": -1},
                        {"scope": "run-wide"}, {"cache_requests": 3},
                        {"envelope_count": 0}):
            with self.subTest(changes=changes):
                doc["observations"]["tool_result_envelopes"] = {**good, **changes}
                with self.assertRaises(Exception):
                    RATBENCH.validate(doc, "rat.benchmark-result/v3")

    def test_optional_by_tool_cache_breakdown_maintains_legacy_compatibility(self):
        older = {
            "scope": "tool-result-envelopes-only", "envelope_count": 2,
            "cache_requests": 2, "cache_hits": 1, "cache_unusable_hits": 0,
            "cache_hit_ratio": 0.5, "captured_stdout_stderr_bytes": None,
        }
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-breakdown", ablation_id="A1",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=2,
            envelope_observations=older,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertNotIn("by_tool", doc["observations"]["tool_result_envelopes"])
        doc["observations"]["tool_result_envelopes"]["by_tool"] = {
            "revq": {"envelope_count": 1, "cache_requests": 1, "cache_hits": 1,
                     "cache_unusable_hits": 0, "cache_hit_ratio": 1.0},
            "decomp": {"envelope_count": 1, "cache_requests": 1, "cache_hits": 0,
                       "cache_unusable_hits": 0, "cache_hit_ratio": 0.0},
        }
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertIsNone(doc["metrics"]["cache"]["cache_hit_ratio"])
        row = doc["observations"]["tool_result_envelopes"]
        for by_tool in (
            None,
            {},
            {**row["by_tool"], "revq": {**row["by_tool"]["revq"], "cache_hits": 0}},
            {**row["by_tool"], "revq": {**row["by_tool"]["revq"], "cache_hit_ratio": float("nan")}},
            {**row["by_tool"], "revq": {**row["by_tool"]["revq"], "cache_hit_ratio": float("inf")}},
            {**row["by_tool"], "revq": {**row["by_tool"]["revq"], "cache_hit_ratio": float("-inf")}},
        ):
            with self.subTest(by_tool=by_tool):
                row["by_tool"] = by_tool
                with self.assertRaises(Exception):
                    RATBENCH.validate(doc, "rat.benchmark-result/v3")

    def test_old_v2_record_without_provenance_or_routing_remains_valid(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-old", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
        )
        self.assertNotIn("provenance", doc)
        self.assertNotIn("routing", doc)
        RATBENCH.validate(doc, "rat.benchmark-result/v3")

    def test_routing_projection_rejects_incoherent_revision_count(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A2",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
            routing_metrics=_routing(route_assessment_count=1, decision_revision_count=1),
        )
        with self.assertRaises(Exception):
            RATBENCH.validate(doc, "rat.benchmark-result/v3")

    def test_empty_routing_projection_is_valid_and_does_not_fabricate_a_route(self):
        empty = {
            "first_dimensions": None, "first_action": None, "first_commitment": None,
            "route_assessment_count": 0, "decision_revision_count": 0,
            "first_skill": None,
        }
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A2",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
            routing_metrics=empty,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertEqual(doc["routing"], empty)

    def test_flag_without_completion_is_only_solve_claimed(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A1",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:10+00:00",
            agent_rc=0, flag_claimed=True,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=1787961604, artifact_count=0,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertEqual(doc["outcome"], "solve-claimed")
        self.assertFalse(doc["metrics"]["correctness"]["verified_solve"])
        self.assertTrue(doc["metrics"]["correctness"]["false_solved"])
        self.assertEqual(doc["oracle"]["failure_class"], "claim-without-completion")
        self.assertIsNone(doc["metrics"]["latency"]["time_to_verified_solve_ms"])

    def test_timeout_without_verified_solve_is_censored(self):
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A2",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:10:00+00:00",
            agent_rc=124, timed_out=True, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertEqual(doc["status"], "timeout")
        self.assertEqual(doc["outcome"], "censored")
        self.assertEqual(doc["oracle"]["failure_class"], "agent-timeout")
        self.assertFalse(doc["metrics"]["correctness"]["false_solved"])
        self.assertIsNone(doc["metrics"]["tools"]["tool_calls"])
        self.assertIsNone(doc["metrics"]["tools"]["duplicate_tool_calls"])

    def test_nonzero_agent_and_missing_completion_have_distinct_observed_failure_classes(self):
        base = dict(
            run_id="B-test", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:01+00:00",
            flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
        )
        nonzero = RATBENCH._mode_b_v2_record(ENTRY, agent_rc=2, **base)
        no_gate = RATBENCH._mode_b_v2_record(ENTRY, agent_rc=0, **base)
        timed_out_claim = RATBENCH._mode_b_v2_record(
            ENTRY, agent_rc=124, timed_out=True, **{**base, "flag_claimed": True})
        for row in (nonzero, no_gate, timed_out_claim):
            RATBENCH.validate(row, "rat.benchmark-result/v3")
            self.assertFalse(row["metrics"]["correctness"]["verified_solve"])
        self.assertEqual(nonzero["oracle"]["failure_class"], "agent-nonzero-exit")
        self.assertEqual(no_gate["oracle"]["failure_class"], "no-verified-completion")
        self.assertEqual(timed_out_claim["oracle"]["failure_class"], "agent-timeout")
        self.assertTrue(timed_out_claim["metrics"]["correctness"]["false_solved"])

    def test_legacy_report_ignores_v2_companion(self):
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "T.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "schema": "rat.bench-result/v2", "run_id": "T", "mode": "B",
                    "id": "fixture-01", "difficulty": 1, "route_ok": False, "outcome": "fail"
                }) + "\n")
            with open(os.path.join(results, "T.benchmark-v3.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"schema": "rat.benchmark-result/v3", "benchmark_run_id": "T"}) + "\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None)), 0)
            with open(os.path.join(d, "bench", "LEADERBOARD.md"), encoding="utf-8") as fh:
                leaderboard = fh.read()
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
            provenance=_provenance(),
        )
        failed = RATBENCH._mode_b_v2_record(
            {**ENTRY, "id": "fixture-02"}, run_id="T", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:08+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=1,
            provenance=_provenance(),
        )
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "T.benchmark-v3.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps(verified) + "\n")
                fh.write(json.dumps(failed) + "\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None, schema="v3")), 0)
            with open(os.path.join(d, "bench", "LEADERBOARD.v3.md"), encoding="utf-8") as fh:
                leaderboard = fh.read()
            self.assertIn("| T | A0 | 2 | 1 | 0 | 1 | 0 | 50.0% |", leaderboard)
            self.assertIn("5000ms (1/2)", leaderboard)
            self.assertIn("4 (1/2)", leaderboard)
            self.assertIn("1 (1/2)", leaderboard)
            self.assertIn("n/a (0/2)", leaderboard)

    def test_v2_report_rejects_mixed_provenance_for_same_run_ablation(self):
        first = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="T", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00", finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0, provenance=_provenance(timeout=600),
        )
        second = RATBENCH._mode_b_v2_record(
            {**ENTRY, "id": "fixture-02"}, run_id="T", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00", finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0, provenance=_provenance(timeout=900),
        )
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "T.benchmark-v3.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps(first) + "\n")
                fh.write(json.dumps(second) + "\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None, schema="v3")), 3)
            self.assertFalse(os.path.exists(os.path.join(d, "bench", "LEADERBOARD.v3.md")))

    def test_v2_report_rejects_mixed_provenance_across_ablations(self):
        first = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="T", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00", finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
            provenance=_provenance(timeout=600),
        )
        second = RATBENCH._mode_b_v2_record(
            {**ENTRY, "id": "fixture-02"}, run_id="T", ablation_id="A1",
            started_at="2026-08-29T00:00:00+00:00", finished_at="2026-08-29T00:00:01+00:00",
            agent_rc=1, flag_claimed=False,
            completion={"verified": False, "reason": "no-active-verification"},
            events=[], primitive_pass_at=None, artifact_count=0,
            provenance=_provenance(timeout=900),
        )
        with self.assertRaisesRegex(ValueError, "comparison run T"):
            RATBENCH._assert_v2_run_provenance([first, second])

    def test_v2_report_rejects_malformed_rows_instead_of_biasing_results(self):
        with tempfile.TemporaryDirectory() as d:
            results = os.path.join(d, "bench", "results")
            os.makedirs(results)
            with open(os.path.join(results, "bad.benchmark-v3.jsonl"), "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            with mock.patch.object(RATBENCH, "ctf_home", return_value=d), mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_report(SimpleNamespace(suite=None, schema="v3")), 3)
            self.assertFalse(os.path.exists(os.path.join(d, "bench", "LEADERBOARD.v3.md")))


if __name__ == "__main__":
    unittest.main()
