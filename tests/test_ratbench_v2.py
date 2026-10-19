import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
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


def require_mode_b_sandbox():
    """Skip real process smoke tests when the host forbids filesystem isolation."""
    with tempfile.TemporaryDirectory() as cwd:
        try:
            result = RATBENCH._run_agent("true", cwd=cwd,
                                         env=RATBENCH._agent_environment(cwd), timeout=5)
        except (OSError, RuntimeError) as exc:
            raise unittest.SkipTest("Mode B filesystem sandbox unavailable: %s" % exc) from exc
        if result.returncode != 0:
            raise unittest.SkipTest("Mode B filesystem sandbox command failed")

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



class RunIdSafetyTests(unittest.TestCase):
    """R2-3: run ids become result filenames; reject traversal and refuse to
    overwrite an existing result."""

    def test_validate_rejects_traversal_and_separators(self):
        for bad in ("../../outside", "a/b", "", ".", "..", "/abs", "x" * 65,
                    "-leading", "with space"):
            with self.subTest(bad=bad):
                with self.assertRaises(RATBENCH.RunIdError):
                    RATBENCH._validate_run_id(bad)

    def test_validate_accepts_safe_slug(self):
        for ok in ("A-123", "release-fix-1", "B.codex.1", "x"):
            with self.subTest(ok=ok):
                self.assertEqual(RATBENCH._validate_run_id(ok), ok)

    def test_result_path_stays_inside_results_dir(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(
                os.path.dirname(RATBENCH._result_path(d, "run1", ".jsonl")),
                os.path.realpath(d))
            # A validated id never contains a separator, but prove the boundary
            # check itself rejects one if reached.
            with self.assertRaises(RATBENCH.RunIdError):
                RATBENCH._result_path(d, "../escape", ".jsonl")

    def test_open_exclusive_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "run1.jsonl")
            with RATBENCH._open_exclusive(path) as fh:
                fh.write("first\n")
            with self.assertRaises(RATBENCH.RunIdError):
                RATBENCH._open_exclusive(path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "first\n")  # original bytes preserved

    def test_cmd_run_refuses_to_overwrite_existing_result(self):
        with tempfile.TemporaryDirectory() as home:
            results = os.path.join(home, "bench", "results")
            os.makedirs(results)
            existing = os.path.join(results, "dup.jsonl")
            with open(existing, "w", encoding="utf-8") as fh:
                fh.write("ORIGINAL\n")
            args = SimpleNamespace(suite=None, corpus=None, id=None, run_id="dup")
            with mock.patch.dict(os.environ, {"CTF_HOME": home}), \
                 mock.patch.object(RATBENCH, "_select_entries", return_value=[ENTRY]), \
                 mock.patch.object(RATBENCH, "_check_route") as route, \
                 mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_run(args), 2)
                route.assert_not_called()  # refused before doing any work
            with open(existing, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "ORIGINAL\n")

    def test_cmd_run_rejects_unsafe_run_id_before_work(self):
        with tempfile.TemporaryDirectory() as home:
            args = SimpleNamespace(suite=None, corpus=None, id=None, run_id="../../outside")
            with mock.patch.dict(os.environ, {"CTF_HOME": home}), \
                 mock.patch.object(RATBENCH, "_select_entries", return_value=[ENTRY]), \
                 mock.patch.object(RATBENCH, "_check_route") as route, \
                 mock.patch("builtins.print"):
                self.assertEqual(RATBENCH.cmd_run(args), 2)
                route.assert_not_called()

    def test_cmd_run_failure_releases_reserved_result(self):
        # A failure after reservation must unlink the empty result so a retry with
        # the same id is not permanently blocked.
        with tempfile.TemporaryDirectory() as home:
            args = SimpleNamespace(suite=None, corpus=None, id=None, run_id="boom")
            with mock.patch.dict(os.environ, {"CTF_HOME": home}), \
                 mock.patch.object(RATBENCH, "_select_entries", return_value=[ENTRY]), \
                 mock.patch.object(RATBENCH, "_check_route", side_effect=RuntimeError("kaboom")), \
                 mock.patch("builtins.print"):
                with self.assertRaises(RuntimeError):
                    RATBENCH.cmd_run(args)
            self.assertFalse(os.path.exists(os.path.join(home, "bench", "results", "boom.jsonl")))


class OutputCapTests(unittest.TestCase):
    """R2-5: a child that floods stdout must hit the output cap and be torn down,
    never read unbounded into memory."""

    @unittest.skipUnless(os.name == "posix", "needs a POSIX shell + process groups")
    def test_flood_raises_output_cap_exceeded(self):
        with tempfile.TemporaryDirectory() as cwd:
            argv = ["/bin/sh", "-c", "yes AAAAAAAA"]  # endless output
            with self.assertRaises(RATBENCH.OutputCapExceeded) as ctx:
                RATBENCH._run_process_tree(argv, cwd=cwd, env=os.environ.copy(),
                                           timeout=30, output_cap=128 * 1024)
            # The captured output is bounded to the cap, not the whole flood.
            self.assertLessEqual(len(ctx.exception.output), 128 * 1024)

    @unittest.skipUnless(os.name == "posix", "needs a POSIX shell")
    def test_small_output_within_cap_succeeds(self):
        with tempfile.TemporaryDirectory() as cwd:
            argv = ["/bin/sh", "-c", "printf 'hello\\n'; exit 0"]
            result = RATBENCH._run_process_tree(argv, cwd=cwd, env=os.environ.copy(),
                                                timeout=30, output_cap=128 * 1024)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"hello\n")

    @unittest.skipUnless(os.name == "posix", "needs a POSIX shell")
    def test_timeout_still_enforced_with_capped_reader(self):
        with tempfile.TemporaryDirectory() as cwd:
            argv = ["/bin/sh", "-c", "sleep 30"]
            with self.assertRaises(subprocess.TimeoutExpired):
                RATBENCH._run_process_tree(argv, cwd=cwd, env=os.environ.copy(),
                                           timeout=1, output_cap=128 * 1024)

    # Child that floods past the cap, then ignores the closed pipe and keeps
    # running (catches BrokenPipeError and sleeps). The overflow must be detected
    # and the group killed immediately, not masked as a plain timeout.
    _FLOOD_THEN_SURVIVE = (
        "import sys,time\n"
        "try:\n"
        " sys.stdout.buffer.write(b'A'*200000); sys.stdout.buffer.flush()\n"
        "except BrokenPipeError: pass\n"
        "for _ in range(100):\n"
        " try: time.sleep(0.3)\n"
        " except BrokenPipeError: pass\n")

    @unittest.skipUnless(os.name == "posix", "needs POSIX process groups")
    def test_overflow_with_surviving_child_is_not_masked_as_timeout(self):
        # Codex P1: _run_process_tree must raise OutputCapExceeded promptly, not
        # wait for the whole timeout, when the over-cap child survives the broken pipe.
        with tempfile.TemporaryDirectory() as cwd:
            argv = [sys.executable, "-c", self._FLOOD_THEN_SURVIVE]
            t0 = time.time()
            with self.assertRaises(RATBENCH.OutputCapExceeded):
                RATBENCH._run_process_tree(argv, cwd=cwd, env={"PATH": "/usr/bin:/bin"},
                                           timeout=20, output_cap=128 * 1024)
            self.assertLess(time.time() - t0, 10)  # well under the 20s timeout

    @unittest.skipUnless(os.name == "posix", "needs POSIX process groups")
    def test_run_capped_overflow_with_surviving_child_returns_overflow_flag(self):
        with tempfile.TemporaryDirectory():
            argv = [sys.executable, "-c", self._FLOOD_THEN_SURVIVE]
            t0 = time.time()
            rc, out, overflowed = RATBENCH._run_capped(
                argv, timeout=20, output_cap=128 * 1024)
            self.assertTrue(overflowed)
            self.assertLessEqual(len(out), 128 * 1024)
            self.assertLess(time.time() - t0, 10)

    @unittest.skipUnless(os.name == "posix", "needs POSIX process groups")
    def test_run_capped_timeout_enforced_when_child_never_reads_stdin(self):
        # Review P1: a child that does not consume its stdin must not let a large
        # synchronous stdin write block past the pipe buffer and defeat the timeout.
        with tempfile.TemporaryDirectory():
            argv = [sys.executable, "-c", "import time; time.sleep(60)"]
            t0 = time.time()
            with self.assertRaises(subprocess.TimeoutExpired):
                RATBENCH._run_capped(argv, input_bytes=b"A" * (4 * 1024 * 1024),
                                     timeout=2, output_cap=128 * 1024)
            self.assertLess(time.time() - t0, 10)  # not blocked for the child's 60s


class ModeBLocalSmokeTests(unittest.TestCase):
    def test_eval_resolves_quoted_agent_executable(self):
        args = SimpleNamespace(agent="'/tmp/agent cli' --version", suite=None, corpus=None, id=None)
        with mock.patch.object(RATBENCH, "_have", return_value=True) as have, \
             mock.patch.object(RATBENCH, "_select_entries", side_effect=LookupError("no entry")), \
             mock.patch("builtins.print"):
            self.assertEqual(RATBENCH.cmd_eval(args), 4)
        have.assert_called_once_with("/tmp/agent cli")

    def test_eval_preflight_accepts_nested_shell_quoting(self):
        command = r'''python3 -c 'print("ok")' "$(printf '"')"'''
        shell = subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True)
        self.assertEqual(shell.returncode, 0, shell.stderr)
        self.assertEqual(shell.stdout, "ok\n")
        args = SimpleNamespace(agent=command, suite=None, corpus=None, id=None)
        with mock.patch.object(RATBENCH, "_have", return_value=True) as have, \
             mock.patch.object(RATBENCH, "_select_entries", side_effect=LookupError("no entry")), \
             mock.patch("builtins.print"):
            self.assertEqual(RATBENCH.cmd_eval(args), 4)
        have.assert_called_once_with("python3")

    def test_eval_preflight_rejects_missing_executable(self):
        args = SimpleNamespace(agent="no-such-agent-ctf-rat --version", suite=None,
                               corpus=None, id=None)
        with mock.patch.object(RATBENCH, "_have", return_value=False), \
             mock.patch.object(RATBENCH, "_select_entries") as entries, \
             mock.patch("builtins.print"):
            self.assertEqual(RATBENCH.cmd_eval(args), 3)
        entries.assert_not_called()

    def test_flag_paths_are_rejected(self):
        for path in ("flag", "flag.txt", "assets/secret.flag"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "flag file"):
                RATBENCH._runtime_fixture_relpath(path)

    def test_agent_wrapper_uses_platform_filesystem_sandbox(self):
        with mock.patch.object(RATBENCH, "ctf_home", return_value="/operator/ctf-rat"), \
             mock.patch.object(RATBENCH, "_have", return_value=True), \
             mock.patch.object(RATBENCH.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
             mock.patch.object(RATBENCH, "_run_process_tree") as execute:
            with mock.patch.object(RATBENCH.sys, "platform", "darwin"):
                with self.assertRaisesRegex(RuntimeError, "verified filesystem and process-tree sandbox"):
                    RATBENCH._run_agent("echo ready", cwd="/tmp/kit/solve/case", env={}, timeout=5)
                execute.assert_not_called()
            with mock.patch.object(RATBENCH.sys, "platform", "linux"):
                RATBENCH._run_agent("echo ready", cwd="/tmp/kit/solve/case",
                                    env={"CTF_HOME": "/tmp/kit"}, timeout=5)
                argv = execute.call_args.args[0]
                self.assertEqual(argv[0], "bwrap")
                self.assertIn("--unshare-pid", argv)
                self.assertIn("--die-with-parent", argv)
                self.assertNotIn(["--ro-bind", "/", "/"], [argv[i:i+3] for i in range(len(argv))])
                self.assertIn(["--bind", "/tmp/kit", "/tmp/kit"],
                              [argv[i:i+3] for i in range(len(argv))])
                self.assertEqual(argv[-3:], ["/bin/sh", "-c", "echo ready"])

    def test_unusable_sandbox_fails_before_agent_command(self):
        failed_probe = SimpleNamespace(returncode=1, stdout=b"user namespaces unavailable")
        with mock.patch.object(RATBENCH, "ctf_home", return_value="/operator/ctf-rat"), \
             mock.patch.object(RATBENCH, "_have", return_value=True), \
             mock.patch.object(RATBENCH.sys, "platform", "linux"), \
             mock.patch.object(RATBENCH.subprocess, "run", return_value=failed_probe) as run:
            with self.assertRaisesRegex(RuntimeError, "filesystem sandbox failed"):
                RATBENCH._run_agent("echo should-not-run", cwd="/tmp/kit/solve/case",
                                    env={"CTF_HOME": "/tmp/kit"}, timeout=5)
        run.assert_called_once()
        self.assertNotIn("should-not-run", run.call_args.args[0])

    def test_agent_environment_drops_host_secrets(self):
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.dict(os.environ, {"UNRELATED_API_TOKEN": "secret",
                                           "SSH_AUTH_SOCK": "/tmp/agent.sock",
                                           "PATH": "/private/bin"}, clear=False), \
             mock.patch.object(RATBENCH, "_have_angr", return_value=False):
            env = RATBENCH._agent_environment(root)
        self.assertNotIn("UNRELATED_API_TOKEN", env)
        self.assertNotIn("SSH_AUTH_SOCK", env)
        self.assertNotIn("/private/bin", env["PATH"])

    def test_timeout_kills_grandchild_before_delayed_write(self):
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "late")
            command = "(sleep 1; touch " + marker + ") & sleep 10"
            with self.assertRaises(subprocess.TimeoutExpired):
                RATBENCH._run_process_tree(["/bin/sh", "-c", command], cwd=root,
                                           env={"PATH": "/usr/bin:/bin"}, timeout=0.1)
            time.sleep(1.2)
            self.assertFalse(os.path.exists(marker))

    def test_mode_b_timeout_kills_detached_child_before_delayed_write(self):
        require_mode_b_sandbox()
        with tempfile.TemporaryDirectory() as root:
            marker = os.path.join(root, "late")
            command = "setsid /bin/sh -c 'sleep 1; touch " + marker + "' </dev/null >/dev/null 2>&1 & wait"
            with self.assertRaises(subprocess.TimeoutExpired):
                RATBENCH._run_agent(command, cwd=root,
                                    env=RATBENCH._agent_environment(root), timeout=0.1)
            time.sleep(1.2)
            self.assertFalse(os.path.exists(marker))

    @unittest.skipUnless(os.name == "posix" and os.path.isfile(sys.executable),
                         "local python interpreter required")
    def test_real_mode_b_exec_without_completion_remains_unverified(self):
        # Execute the actual Mode B workspace/export + external process path.
        # This is a negative-gate smoke, NOT a model-solving benchmark.
        require_mode_b_sandbox()
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

    def test_output_overflow_override_is_not_verified_even_with_prior_completion(self):
        # R2-5 (re-open #2): on an output flood cmd_eval passes an overridden
        # completion (verified=False) and flag_claimed=False; the v3 record must not
        # report a verified/solved outcome even though a verification event exists.
        events = [
            {"type": "verification.recorded", "at": "2026-08-29T00:00:05+00:00",
             "payload": {"verification_id": "verify_1"}},
        ]
        doc = RATBENCH._mode_b_v2_record(
            ENTRY, run_id="B-test", ablation_id="A0",
            started_at="2026-08-29T00:00:00+00:00",
            finished_at="2026-08-29T00:00:06+00:00",
            agent_rc=125, flag_claimed=False,
            completion={"verified": False, "reason": "output cap exceeded; run untrusted",
                        "verification_id": "verify_1"},
            events=events, primitive_pass_at=None, artifact_count=0,
            provenance=_provenance(), routing_metrics=_routing(),
        )
        RATBENCH.validate(doc, "rat.benchmark-result/v3")
        self.assertNotEqual(doc["outcome"], "verified")
        self.assertFalse(doc["metrics"]["correctness"]["verified_solve"])
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


import shutil


@unittest.skipUnless(shutil.which("gcc"), "gcc required for flag-regex verify fixture")
class FlagRegexVerifyHonesty(unittest.TestCase):
    """R0-2: flag-regex must require a clean exit and a bounded output, never a
    pattern match on failing/huge output."""

    def _build(self, body):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        src = os.path.join(d, "f.c")
        with open(src, "w") as fh:
            fh.write(body)
        exe = os.path.join(d, "f")
        subprocess.run(["gcc", "-w", "-O0", src, "-o", exe], check=True)
        return exe

    def test_pattern_match_with_nonzero_exit_is_not_success(self):
        exe = self._build('#include <stdio.h>\nint main(){puts("FLAG{x}");return 1;}\n')
        entry = {"verify": {"kind": "flag-regex", "pattern": r"FLAG\{.+\}"}}
        status, detail = RATBENCH._verify_flag_regex(entry, exe)
        self.assertEqual(status, "verify-fail")
        self.assertIn("exit 1", detail)

    def test_clean_exit_and_match_passes(self):
        exe = self._build('#include <stdio.h>\nint main(){puts("FLAG{ok}");return 0;}\n')
        entry = {"verify": {"kind": "flag-regex", "pattern": r"FLAG\{.+\}"}}
        status, detail = RATBENCH._verify_flag_regex(entry, exe)
        self.assertEqual(status, "pass")

    def test_output_flood_is_rejected(self):
        # Prints far more than the cap, then exits 0 with the pattern present.
        exe = self._build('#include <stdio.h>\nint main(){for(long i=0;i<200000;i++)puts("FLAG{x}");return 0;}\n')
        entry = {"verify": {"kind": "flag-regex", "pattern": r"FLAG\{.+\}"}}
        status, detail = RATBENCH._verify_flag_regex(entry, exe)
        self.assertEqual(status, "verify-fail")
        self.assertIn("exceeded", detail)


class SymsolveVerifyHonesty(unittest.TestCase):
    """R0-3: symsolve-restore must require exit 0 + a result contract with
    concrete_verify==pass + the expected plaintext in a recovered solution.
    Fake successes (stdout string with exit 1, missing/mismatched contract) fail."""

    ENTRY = {"verify": {"kind": "symsolve-restore", "expected": "s3cr3t",
                        "find_str": "FLAG", "avoid_str": "Wrong", "stdin_len": 6}}

    def _patched(self, returncode, result_doc, overflow=False):
        """Run _verify_symsolve with the bounded child runner and angr stubbed so we
        drive only the consumer-side contract checks deterministically."""
        import contextlib

        @contextlib.contextmanager
        def ctx():
            def fake_run_capped(cmd, **kw):
                # cmd carries "--result <path>"; write the fixture doc there.
                rp = cmd[cmd.index("--result") + 1]
                if result_doc is not None:
                    with open(rp, "w") as fh:
                        json.dump(result_doc, fh)
                return (returncode, b"FLAG recovered: s3cr3t\n", overflow)
            with mock.patch.object(RATBENCH, "_run_capped", fake_run_capped), \
                 mock.patch.object(RATBENCH, "_have_angr", return_value=True), \
                 mock.patch.object(RATBENCH, "_angr_python", return_value="python3"):
                yield
        return ctx()

    def _good_doc(self, **over):
        doc = {"schema": "rat.symsolve-result/v1", "found": True,
               "concrete_verify": "pass", "verified": True,
               "solutions": {"stdin": b"s3cr3t".hex()}}
        doc.update(over)
        return doc

    def test_stdout_string_with_nonzero_exit_is_not_success(self):
        with self._patched(1, self._good_doc()):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")

    def test_missing_result_contract_fails(self):
        with self._patched(0, None):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")

    def test_concrete_verify_mismatch_fails(self):
        with self._patched(0, self._good_doc(concrete_verify="fail", verified=False)):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")

    def test_skipped_verify_is_not_success(self):
        with self._patched(0, self._good_doc(concrete_verify="skipped", verified=False)):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")

    def test_wrong_solution_fails_even_if_contract_passes(self):
        with self._patched(0, self._good_doc(solutions={"stdin": b"wrong!".hex()})):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")

    def test_full_pass_contract_and_solution(self):
        with self._patched(0, self._good_doc()):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "pass")

    def test_non_object_result_is_verify_fail_not_crash(self):
        # R0-3 (re-open #3): a list/null/string top-level result must be a bounded
        # verify-fail, never an AttributeError.
        for doc in ([], None, "nope", 42):
            with self.subTest(doc=doc):
                with self._patched(0, doc):
                    status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
                self.assertEqual(status, "verify-fail")

    def test_non_object_solutions_is_verify_fail_not_crash(self):
        # R0-3 (re-open #3): solutions must be an object; a list would crash on
        # .values() otherwise.
        with self._patched(0, self._good_doc(solutions=[b"s3cr3t".hex()])):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")
        self.assertIn("solutions", detail)

    def test_symsolve_output_overflow_is_verify_fail(self):
        # R2-5 (re-open #5): symsolve child output flood -> verify-fail, never pass.
        with self._patched(0, self._good_doc(), overflow=True):
            status, detail = RATBENCH._verify_symsolve(self.ENTRY, "/bin/true")
        self.assertEqual(status, "verify-fail")
        self.assertIn("exceeded", detail)


@unittest.skipUnless(RATBENCH._have("gcc"), "needs gcc to distinguish compile-failure from skip")
class CompileFailureHonesty(unittest.TestCase):
    """R2-4: a broken C fixture must become a verify-fail, never a silent skip,
    when the compiler itself is present."""

    def _entry_dir(self, body):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        rel = os.path.join("bench", "artifacts", "compile-fixture")
        os.makedirs(os.path.join(home, rel), exist_ok=True)
        with open(os.path.join(home, rel, "src.c"), "w") as fh:
            fh.write(body)
        return home, {"id": "compile-fixture", "dir": rel}

    def test_broken_source_raises_compile_error_not_none(self):
        home, entry = self._entry_dir("int main(void){ this is not C }\n")
        with mock.patch.dict(os.environ, {"CTF_HOME": home}):
            with tempfile.TemporaryDirectory() as work:
                with self.assertRaises(RATBENCH.CompileError):
                    RATBENCH._compile(entry, work)

    def test_cmd_run_reports_broken_fixture_as_verify_fail(self):
        # Drive the actual Mode A loop decision: compile failure -> verify-fail,
        # distinct from "route-ok-verify-skipped".
        home, entry = self._entry_dir("int main(void){ nonsense ; }\n")
        with mock.patch.dict(os.environ, {"CTF_HOME": home}):
            with tempfile.TemporaryDirectory() as work:
                with self.assertRaises(RATBENCH.CompileError):
                    RATBENCH._compile(entry, work)
                # The caller maps CompileError -> verify-fail (see cmd_run).
                try:
                    RATBENCH._compile(entry, work)
                except RATBENCH.CompileError as exc:
                    status, detail = "verify-fail", "fixture compile failed: %s" % exc
                self.assertEqual(status, "verify-fail")
                self.assertIn("compile failed", detail)

    def test_missing_source_still_skips(self):
        # No src.c at all -> genuine skip (None), not a CompileError.
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        rel = os.path.join("bench", "artifacts", "empty-fixture")
        os.makedirs(os.path.join(home, rel), exist_ok=True)
        entry = {"id": "empty-fixture", "dir": rel}
        with mock.patch.dict(os.environ, {"CTF_HOME": home}):
            with tempfile.TemporaryDirectory() as work:
                self.assertIsNone(RATBENCH._compile(entry, work))

    def test_good_source_compiles(self):
        home, entry = self._entry_dir("int main(void){ return 0; }\n")
        with mock.patch.dict(os.environ, {"CTF_HOME": home}):
            with tempfile.TemporaryDirectory() as work:
                out = RATBENCH._compile(entry, work)
                self.assertTrue(out and os.path.isfile(out))


if __name__ == "__main__":
    unittest.main()
