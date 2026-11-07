"""E2E checks for bounded large-input function work and semantic scope."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "bin"
sys.path.insert(0, str(BIN))


def _angr_reachable():
    # revq's bounded-function path re-execs into .venv-angr; without a reachable
    # angr these tests can only observe the clean dependency_missing error, not the
    # analysis behavior they assert, so they skip (the non-angr regression lane).
    try:
        from ratlib.angr_runtime import configured_python
        return bool(configured_python()) or importlib.util.find_spec("angr") is not None
    except Exception:
        return False


ANGR = _angr_reachable()


def revq_module():
    sys.path.insert(0, str(BIN))
    loader = importlib.machinery.SourceFileLoader("_test_large_revq", str(BIN / "revq"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class LargeBinaryAnalysisPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("gcc"):
            raise unittest.SkipTest("gcc unavailable")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.small = Path(cls.tmp.name) / "semantic"
        cls.large = Path(cls.tmp.name) / "large"
        subprocess.run(["gcc", "-w", "-O0", "-fno-stack-protector", "-no-pie",
                        str(REPO / "bench" / "large_binary_semantic.c"), "-o", str(cls.small)],
                       check=True, capture_output=True, timeout=30)
        cls.large.write_bytes(cls.small.read_bytes() + b"\0" * (4 * 1024 * 1024 - cls.small.stat().st_size))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @unittest.skipUnless(ANGR, "bounded angr analysis requires angr reachable")
    def test_function_region_matches_full_main_and_marks_partial(self):
        full = subprocess.run([str(BIN / "revq"), str(self.small), "--refresh", "--format", "json"],
                              capture_output=True, text=True, timeout=30, check=True)
        rev = json.loads(full.stdout)
        baseline = next(f for f in rev["functions"] if f["name"] == "main")
        local = subprocess.run([str(BIN / "revq"), str(self.large), "--func", "main"],
                               capture_output=True, text=True, timeout=30, check=True)
        card = json.loads(local.stdout)
        self.assertEqual(card["function"]["size"], baseline["size"])
        self.assertEqual(card["function"]["ninstr"], baseline["ninstr"])
        self.assertEqual(card["facts"]["callees"], baseline["calls"])
        self.assertEqual(card["facts"]["strings"], baseline["strings"])
        self.assertEqual(card["facts"]["call_sites"], baseline["call_sites"])
        self.assertEqual(card["provenance"]["scope"]["range_quality"], "elf-symbol-range")
        self.assertTrue(any(item["kind"] == "function_scope" for item in card["unresolved"]))
        cache_files = list(self.large.parent.glob(self.large.name + ".func-*.revq.json"))
        self.assertEqual(len(cache_files), 1)
        before = cache_files[0].stat().st_mtime_ns
        cached = subprocess.run([str(BIN / "revq"), str(self.large), "--func", "main"],
                                capture_output=True, text=True, timeout=30, check=True)
        self.assertEqual(json.loads(cached.stdout), card)
        self.assertEqual(cache_files[0].stat().st_mtime_ns, before)

    @unittest.skipUnless(ANGR, "bounded angr analysis requires angr reachable")
    def test_raw_blob_cache_is_keyed_by_arch(self):
        # Regression: the function-region cache key omitted load_spec.  A raw blob
        # queried over the same address range first with --arch i386 and then with
        # --arch amd64 shares addr/end (both come from the operator-supplied target
        # +size), so the second query returned the cached X86 (i386) analysis
        # instead of decoding the bytes as AMD64.  The two arches must now produce
        # distinct cache files and distinct results.
        blob = Path(self.tmp.name) / "blob-arch"
        blob.write_bytes(self.large.read_bytes())
        # Target a REAL .text address of the (no-pie) fixture, not the ELF-header
        # region: decoding actual x86 code yields a function under both arches, so
        # the test exercises the cache key rather than an arch's ability to form a
        # function out of arbitrary header bytes.  main's VMA == its file-mapped
        # address here (no-pie, base 0x400000).
        main_addr = None
        for line in subprocess.check_output(["nm", str(self.small)], text=True).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] == "main" and parts[1] in ("T", "t"):
                main_addr = hex(int(parts[0], 16))
        self.assertIsNotNone(main_addr, "control binary has no main symbol")
        common = ["--func", main_addr, "--func-size", "96",
                  "--base", "0x400000", "--entry", "0x400000", "--format", "json"]
        r_i386 = subprocess.run([str(BIN / "revq"), str(blob), "--arch", "i386", *common],
                                capture_output=True, text=True, timeout=60)
        r_amd64 = subprocess.run([str(BIN / "revq"), str(blob), "--arch", "amd64", *common],
                                 capture_output=True, text=True, timeout=60)
        self.assertEqual(r_i386.returncode, 0, r_i386.stderr[-400:])
        self.assertEqual(r_amd64.returncode, 0, r_amd64.stderr[-400:])
        doc_amd64 = json.loads(r_amd64.stdout)
        # Each arch wrote its own cache file; a shared key would leave only one and
        # the amd64 query would have been served the cached i386 analysis.
        cache_files = sorted(blob.parent.glob(blob.name + ".func-*.revq.json"))
        self.assertEqual(len(cache_files), 2,
                         "each --arch must get its own function-region cache entry")
        archs = set()
        for cache in cache_files:
            spec = json.loads(cache.read_text()).get("load_spec")
            self.assertIsNotNone(spec, "blob cache entry must record its load_spec")
            archs.add(spec["arch"])
        self.assertEqual(archs, {"X86", "AMD64"},
                         "the two cache entries must decode as different arches")
        # Re-running amd64 hits its own cache (no new file).
        before = {p.name: p.stat().st_mtime_ns for p in cache_files}
        again = subprocess.run([str(BIN / "revq"), str(blob), "--arch", "amd64", *common],
                               capture_output=True, text=True, timeout=60, check=True)
        self.assertEqual(json.loads(again.stdout), doc_amd64)
        after = {p.name: p.stat().st_mtime_ns for p in
                 blob.parent.glob(blob.name + ".func-*.revq.json")}
        self.assertEqual(before, after, "amd64 re-query must hit cache, not rewrite")

    @unittest.skipUnless(ANGR, "bounded angr analysis requires angr reachable")
    def test_numeric_scope_requires_explicit_size(self):
        result = subprocess.run([str(BIN / "revq"), str(self.large), "--func", "0x401000"],
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--func-size", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(ANGR, "bounded angr analysis requires angr reachable")
    def test_size_refusal_explicit_full_override_and_cache_hit(self):
        fresh = Path(self.tmp.name) / "override-case"
        fresh.write_bytes(self.large.read_bytes())
        command = [str(BIN / "revq"), str(fresh), "--funcs", "--format", "json"]
        refused = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("RAT_STATUS=partial", refused.stderr)
        explicit = subprocess.run(command + ["--allow-large"], capture_output=True,
                                  text=True, timeout=30, check=True)
        self.assertGreater(json.loads(explicit.stdout)["counts"]["functions_total"], 0)
        cached = subprocess.run(command, capture_output=True, text=True, timeout=20, check=True)
        self.assertIn("캐시 사용", cached.stderr)
        self.assertEqual(json.loads(cached.stdout)["counts"], json.loads(explicit.stdout)["counts"])

    @unittest.skipUnless(ANGR, "bounded angr analysis requires angr reachable")
    def test_rat_function_frontdoor_keeps_partial_coverage(self):
        result = subprocess.run([str(BIN / "rat"), "query", "func", str(self.large), "main",
                                 "--format", "json"], capture_output=True, text=True,
                                timeout=30, check=True)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "partial")
        self.assertFalse(doc["coverage"]["complete"])
        self.assertIn("function_scope", doc["coverage"]["omitted"]["unresolved"])

    @unittest.skipUnless(ANGR, "bounded angr analysis requires angr reachable")
    def test_rat_query_func_scope_required_returns_clean_error_not_crash(self):
        # Regression: _revq_error_response mapped scope_required -> input_required,
        # a code the query-result schema's allow-list did not contain, so _emit's
        # validation raised ValidationError and the command crashed with a
        # traceback.  A numeric --func on an oversized binary with no --func-size
        # hits scope_required; it must return a clean error envelope, not crash.
        result = subprocess.run([str(BIN / "rat"), "query", "func", str(self.large),
                                 "0x401500", "--format", "json"],
                                capture_output=True, text=True, timeout=30)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("ValidationError", result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc["status"], "error")
        self.assertEqual([d["code"] for d in doc["diagnostics"]], ["input_required"])

    def test_rat_query_graph_size_cap_is_not_dependency_missing(self):
        # Regression: `rat query graph` on a >2MiB binary hits the angr size cap
        # (revq AngrAnalysisError kind=size_limit).  That must surface as
        # `analysis_unavailable` (the same code `rat query func` uses), not be
        # flattened to `dependency_missing`, which wrongly tells the user a
        # dependency is missing when the real cause is the input-size guard.
        result = subprocess.run([str(BIN / "rat"), "query", "graph", str(self.large),
                                 "--format", "json"], capture_output=True, text=True,
                                timeout=30)
        doc = json.loads(result.stdout)
        codes = {d["code"] for d in doc["diagnostics"]}
        self.assertIn("analysis_unavailable", codes,
                      "size-cap must map to analysis_unavailable, got %s" % codes)
        self.assertNotIn("dependency_missing", codes)

    def test_worker_timeout_is_typed(self):
        revq = revq_module()
        fake = mock.Mock(timed_out=True, resource_limited=False, exit_code=124,
                         signal=None, stderr=mock.Mock(preview=b""))
        with mock.patch.object(revq, "run", return_value=fake):
            with self.assertRaises(revq.AngrAnalysisError) as caught:
                revq._extract_angr_bounded(str(self.large), None, False)
        self.assertEqual(caught.exception.kind, "timeout")

    def test_worker_sigsegv_is_typed_resource_limit(self):
        # A native CFGFast allocation over the worker's RLIMIT_AS crashes it with
        # SIGSEGV (not a Python MemoryError / SIGKILL), so the worker emits no OOM
        # marker.  That must be reported as resource_limit (raise the budget), not
        # a generic analysis_failed that hides the actual remedy.
        import signal as _signal
        revq = revq_module()
        fake = mock.Mock(timed_out=False, resource_limited=False, exit_code=-_signal.SIGSEGV,
                         signal=_signal.SIGSEGV, stderr=mock.Mock(preview=b""))
        with mock.patch.object(revq, "run", return_value=fake):
            with self.assertRaises(revq.AngrAnalysisError) as caught:
                revq._extract_angr_bounded(str(self.large), None, False)
        self.assertEqual(caught.exception.kind, "resource_limit")

    def test_worker_nonmemory_failure_stays_analysis_failed(self):
        # A non-signal worker failure with no OOM marker is a real analysis error,
        # not a budget problem -- it must NOT be upgraded to resource_limit.
        revq = revq_module()
        fake = mock.Mock(timed_out=False, resource_limited=False, exit_code=70,
                         signal=None, stderr=mock.Mock(preview=b"RAT_ANGR_WORKER_ERROR: ValueError: x"))
        with mock.patch.object(revq, "run", return_value=fake):
            with self.assertRaises(revq.AngrAnalysisError) as caught:
                revq._extract_angr_bounded(str(self.large), None, False)
        self.assertEqual(caught.exception.kind, "analysis_failed")

    def test_ghidra_noanalysis_reports_partial_function(self):
        sys.path.insert(0, str(BIN))
        from ratlib.ghidra import resolve_analyze_headless
        if not resolve_analyze_headless():
            self.skipTest("Ghidra unavailable")
        symbols = subprocess.check_output(["nm", "-n", str(self.large)], text=True, timeout=10)
        address = next(int(line.split()[0], 16) for line in symbols.splitlines()
                       if line.endswith(" main"))
        run = subprocess.run([str(BIN / "decomp-local"), str(self.large), hex(address),
                              "--timeout", "45", "--refresh", "--format", "json"],
                             capture_output=True, text=True, timeout=55)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout[-1000:])
        doc = json.loads(run.stdout)
        self.assertEqual(doc["status"], "partial")
        self.assertFalse(doc["coverage"]["whole_program"])
        self.assertIn("main", doc["content"])

    def test_decomp_local_reuses_ghidra_project_across_functions(self):
        # Regression for project reuse: analyzing a second function of the SAME
        # binary must re-open the persisted Ghidra project (-process), not import a
        # second copy.  A duplicate import would create a second program entry.
        sys.path.insert(0, str(BIN))
        from ratlib.ghidra import resolve_analyze_headless
        if not resolve_analyze_headless():
            self.skipTest("Ghidra unavailable")
        symbols = subprocess.check_output(["nm", "-n", str(self.small)], text=True, timeout=10)
        funcs = {parts[2]: int(parts[0], 16)
                 for line in symbols.splitlines()
                 if len(parts := line.split()) == 3 and parts[1] in ("t", "T")}
        picked = [funcs[n] for n in ("main",) if n in funcs]
        picked += [a for n, a in sorted(funcs.items()) if a not in picked][:1]
        if len(picked) < 2:
            self.skipTest("need two text-symbol functions in the control binary")
        project_dir = self.small.parent / "rat-ghidra-projects"
        shutil.rmtree(project_dir, ignore_errors=True)
        shutil.rmtree(self.small.parent / ".rat" / "decomp-local", ignore_errors=True)
        for addr in picked:
            run = subprocess.run([str(BIN / "decomp-local"), str(self.small), hex(addr),
                                  "--timeout", "45", "--refresh", "--format", "json"],
                                 capture_output=True, text=True, timeout=55)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout[-800:])
            self.assertEqual(json.loads(run.stdout)["status"], "partial")
        # Exactly one persisted project exists, and it imported the program once:
        # the per-program metadata directory (p.rep/idata) holds a single entry.
        projects = list(project_dir.glob("proj-*/p.gpr"))
        self.assertEqual(len(projects), 1, "expected a single reused project")
        idata = projects[0].parent / "p.rep" / "idata"
        imported = [p for p in idata.rglob("*.prp") if p.name != "project.prp"]
        self.assertEqual(len(imported), 1,
                         "a second -import would add a duplicate program entry: %r" % imported)

    def test_decomp_local_rebuilds_a_corrupt_persisted_project(self):
        # Regression: a -process run against a stale/corrupt/locked project (e.g.
        # left by a killed earlier run) must fall back to re-import, not fail every
        # subsequent query of that binary forever.
        sys.path.insert(0, str(BIN))
        from ratlib.ghidra import resolve_analyze_headless
        if not resolve_analyze_headless():
            self.skipTest("Ghidra unavailable")
        symbols = subprocess.check_output(["nm", "-n", str(self.small)], text=True, timeout=10)
        address = next(int(line.split()[0], 16) for line in symbols.splitlines()
                       if line.endswith(" main"))
        project_dir = self.small.parent / "rat-ghidra-projects"
        shutil.rmtree(project_dir, ignore_errors=True)
        shutil.rmtree(self.small.parent / ".rat" / "decomp-local", ignore_errors=True)
        # First run creates the persisted project.
        first = subprocess.run([str(BIN / "decomp-local"), str(self.small), hex(address),
                                "--timeout", "45", "--refresh", "--format", "json"],
                               capture_output=True, text=True, timeout=55)
        self.assertEqual(json.loads(first.stdout)["status"], "partial", first.stderr[-400:])
        gpr = next(project_dir.glob("proj-*/p.gpr"))
        gpr.write_text("corrupt")  # make the -process re-open fail
        # Second run must detect the broken project and rebuild via -import.
        second = subprocess.run([str(BIN / "decomp-local"), str(self.small), hex(address),
                                 "--timeout", "45", "--refresh", "--format", "json"],
                                capture_output=True, text=True, timeout=55)
        self.assertEqual(json.loads(second.stdout)["status"], "partial",
                         "corrupt project was not rebuilt: %s" % second.stdout[-400:])


if __name__ == "__main__":
    unittest.main()
