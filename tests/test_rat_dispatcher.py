"""Subprocess e2e for the M4 `bin/rat` front door.

Some cases below need a real ELF + angr (docker/dev per CLAUDE.md's fixed
test env) and are skipped elsewhere: `--mode data` slicing, and anything
that depends on `bin/ratlib/runner.run()`'s resource limits, which are
Linux-only (RLIMIT_AS) and make `rat-profile`/`rat-slice`/`rat-doctor`'s
regression-adjacent subprocess plumbing fail on a non-Linux host. The
input-validation / degradation paths that don't need a working analysis
engine are exercised unconditionally.
"""
import json, os, pathlib, shutil, subprocess, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
from ratlib.schema import validate

LINUX = sys.platform.startswith("linux")
HAS_ANGR = False
try:
    import angr  # noqa: F401
    HAS_ANGR = True
except ImportError:
    pass

def run_rat(*args, timeout=60, cwd=None):
    p = subprocess.run([str(BIN / "rat"), *map(str, args)], text=True, capture_output=True, timeout=timeout, cwd=cwd)
    return p.returncode, p.stdout, p.stderr

class SelftestAndUsage(unittest.TestCase):
    def test_selftest_is_pure_and_green_without_a_binary(self):
        code, out, err = run_rat("selftest")
        self.assertEqual(code, 0, err)
        self.assertIn("OK", out)

    def test_no_subcommand_prints_help_and_exits_usage(self):
        code, _, _ = run_rat()
        self.assertEqual(code, 2)

class InputValidation(unittest.TestCase):
    """These don't need angr/ELF/docker -- missing-binary is a pure guard."""
    def test_route_missing_binary_is_input_error(self):
        code, out, _ = run_rat("route", "/definitely/missing", "--format", "json")
        self.assertEqual(code, 4)
        doc = json.loads(out)
        validate(doc, "rat.route-result/v1")
        self.assertEqual(doc["error"]["code"], "input_invalid")

    def test_query_func_missing_binary_is_input_error(self):
        code, out, _ = run_rat("query", "func", "/definitely/missing", "main", "--format", "json")
        self.assertEqual(code, 4)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")
        self.assertEqual(doc["status"], "error")
        self.assertEqual(doc["diagnostics"][0]["code"], "input_invalid")

    def test_query_oracle_missing_binary_is_input_error(self):
        code, out, _ = run_rat("query", "oracle", "/definitely/missing", "--format", "json")
        self.assertEqual(code, 4)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")

    def test_query_slice_missing_binary_is_input_error(self):
        code, out, _ = run_rat("query", "slice", "/definitely/missing", "--backward", "0x1000", "--format", "json")
        self.assertEqual(code, 4)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")

class CacheStats(unittest.TestCase):
    """Pure sqlite introspection -- no analysis engine needed."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = os.path.join(self.tmp.name, ".rat")

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_store_reports_zero_entries(self):
        code, out, err = run_rat("cache", "stats", "--store", self.store, "--format", "json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        validate(doc, "rat.cache-stats/v1")
        self.assertEqual(doc["total_entries"], 0)

    def test_populated_store_counts_entries(self):
        sys.path.insert(0, str(BIN))
        from ratlib.cache import Cache
        c = Cache(self.store)
        c.put_entry("k1", backend="fs", path="/a")
        c.put_entry("k2", backend="fs", path="/b")
        code, out, err = run_rat("cache", "stats", "--store", self.store, "--format", "json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["total_entries"], 2)
        self.assertEqual(doc["by_backend"], {"fs": 2})

class GovernorWiring(unittest.TestCase):
    """route degrades to the same 'unknown' novelty-free result every time for
    a binary with no signal at all -- the 5th call must carry a stuck governor
    block. Needs no angr/ELF: the degraded route is deterministic either way."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self.tmp.name, "silent")
        with open(self.binary, "wb") as f:
            f.write(b"\x00" * 16)  # not ELF/PE/Mach-O -- guarantees an unchanging degraded route
        os.chmod(self.binary, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sixth_identical_route_call_reports_governor_stuck(self):
        # check_progress needs `window` (5) *consecutive non-novel* actions;
        # call #1 is always novel (nothing seen yet), so the earliest a fully
        # non-novel 5-window can appear is calls #2-#6 -- i.e. the 6th call.
        docs = []
        for _ in range(6):
            code, out, err = run_rat("route", self.binary, "--format", "json")
            self.assertEqual(code, 0, err)
            docs.append(json.loads(out))
        for d in docs:
            validate(d, "rat.route-result/v1")
        self.assertNotIn("governor", docs[0])
        self.assertIn("governor", docs[-1])
        self.assertTrue(docs[-1]["governor"]["stuck"])
        self.assertEqual(docs[-1]["governor"]["action"], "re-route-or-deep-escalate")

    def test_state_progress_between_identical_calls_prevents_false_stuck(self):
        # Same 5 identical calls that make the 6th call "stuck" above -- but
        # with a real STATE v2 progress event recorded before the 6th call,
        # the governor must see that as novel even though the route result
        # itself hasn't changed.
        from ratlib.state_v2 import Stream
        for _ in range(5):
            code, out, err = run_rat("route", self.binary, "--format", "json")
            self.assertEqual(code, 0, err)
        Stream(self.tmp.name).append("route.ruled_out", {"fingerprint": "dead-end-1", "text": "ruled out"})
        code, out, err = run_rat("route", self.binary, "--format", "json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertNotIn("governor", doc)

class FrontDoorTextRendering(unittest.TestCase):
    """Default text output must surface the route-result's essential fields,
    not collapse to a bare `label: status` line."""
    def test_route_text_output_shows_track_confidence_skill_next(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "silent")
            with open(binary, "wb") as f:
                f.write(b"\x00" * 16)
            os.chmod(binary, 0o755)
            code, out, err = run_rat("route", binary)
            self.assertEqual(code, 0, err)
            self.assertIn("ROUTE", out)
            self.assertIn("CONFIDENCE", out)
            self.assertIn("SKILL", out)
            self.assertIn("NEXT", out)

class DynVerifyStateCompactPassthrough(unittest.TestCase):
    """Pure argv-forwarding -- exercised against a legacy CLI's own usage/
    error path so no analysis engine is required."""
    def test_state_compact_forwards_to_legacy_state_tool(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, err = run_rat("state", "compact", "--budget-tokens", "500", cwd=d)
            self.assertEqual(code, 0, err)
            doc = json.loads(out)
            self.assertEqual(set(doc), {"invalidating_findings", "confirmed_findings", "pass_primitives",
                                         "hypotheses", "next_probes", "ruled_out", "truncated", "omitted_counts", "cursor",
                                         "budget_tokens", "estimated_tokens", "budget_exceeded_by_critical_tiers"})

    def test_dyn_missing_required_flags_matches_legacy_exit_code(self):
        legacy = subprocess.run([str(BIN / "rat-dyn"), "/bin/true"], text=True, capture_output=True)
        code, out, err = run_rat("dyn", "/bin/true")
        self.assertEqual(code, legacy.returncode)

    def test_verify_missing_required_flags_matches_legacy_exit_code(self):
        legacy = subprocess.run([str(BIN / "rat-verify"), "/bin/true"], text=True, capture_output=True)
        code, out, err = run_rat("verify", "/bin/true")
        self.assertEqual(code, legacy.returncode)

@unittest.skipUnless(LINUX and HAS_ANGR and shutil.which("gcc"), "needs Linux + angr + gcc (docker/dev per CLAUDE.md)")
class FullEngineDependent(unittest.TestCase):
    """Real ELF + angr path: function-card remap, oracle wiring, data slice.
    Skipped outside docker/dev; see CLAUDE.md's fixed verification env."""
    FIX = ROOT / "tests" / "fixtures" / "analysis"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.work = pathlib.Path(self.tmp.name)
        self.exe = self.work / "toy"
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", str(self.FIX / "toy.c"), "-o", str(self.exe)], check=True)
        self.store = str(self.work / "store")

    def tearDown(self):
        self.tmp.cleanup()

    def test_query_func_main_is_ok_and_schema_valid(self):
        code, out, err = run_rat("query", "func", str(self.exe), "main", "--store", self.store, "--format", "json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")
        self.assertIn(doc["status"], ("ok", "partial"))

    def test_query_func_not_found_is_input_invalid(self):
        code, out, err = run_rat("query", "func", str(self.exe), "no_such_function", "--store", self.store, "--format", "json")
        self.assertEqual(code, 4)
        doc = json.loads(out)
        self.assertEqual(doc["diagnostics"][0]["code"], "input_invalid")

    def test_query_slice_never_puts_claim_in_facts(self):
        code, out, err = run_rat("query", "slice", str(self.exe), "--backward", "0x1000",
                                  "--store", self.store, "--format", "json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")
        self.assertNotIn("claim", doc["facts"])
        self.assertIn("claim", doc["heuristics"])

    def test_route_with_custom_store_registers_revq_in_the_same_index(self):
        # A custom --store must be the one canonical index for every backend
        # `rat route` touches -- rat-profile and revq must not diverge onto
        # the default dirname(binary)/.rat index.
        code, out, err = run_rat("route", str(self.exe), "--store", self.store, "--format", "json")
        self.assertEqual(code, 0, err)
        default_index = self.exe.parent / ".rat" / "indexes" / "cache.sqlite3"
        self.assertFalse(default_index.exists())
        custom_index = pathlib.Path(self.store) / "indexes" / "cache.sqlite3"
        self.assertTrue(custom_index.exists())
        rows = subprocess.run(["sqlite3", str(custom_index), "select distinct backend from cache"],
                               text=True, capture_output=True, check=True).stdout
        self.assertIn("revq_json", rows)
        self.assertIn("profile_artifact", rows)

    def test_governor_reads_challenge_state_not_custom_store(self):
        # `--store` overrides only the cache/index location; the solving STATE
        # namespace the governor reads progress from must stay anchored to the
        # binary. A store whose parent is NOT the challenge dir would, under the
        # old `Stream(dirname(store))` wiring, make the governor read/write a
        # stray STATE and go blind to real progress.
        far = tempfile.TemporaryDirectory(); self.addCleanup(far.cleanup)
        store = str(pathlib.Path(far.name) / "cache" / "store")
        code, out, err = run_rat("route", str(self.exe), "--store", store, "--format", "json")
        self.assertEqual(code, 0, err)
        chal_stream = self.exe.parent / ".rat" / "events" / "STATE.v2.jsonl"
        self.assertTrue(chal_stream.exists(), "governor must write STATE next to the binary")
        types = [json.loads(l)["type"] for l in chal_stream.read_text().splitlines() if l.strip()]
        self.assertIn("governor.checked", types)
        stray = pathlib.Path(store).parent / ".rat" / "events" / "STATE.v2.jsonl"
        self.assertFalse(stray.exists(), "custom --store must not relocate the STATE namespace")

    def test_query_oracle_bounds_projection_but_keeps_exact_counts(self):
        # Query-First v2: a single oracle query must not blow up context even on
        # a binary with many success/failure-like strings. The projection is
        # budget-bounded while the counts (which drive auto_connect) stay exact.
        code, out, err = run_rat("query", "oracle", str(self.exe), "--store", self.store,
                                  "--budget-bytes", "1", "--format", "json")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        validate(doc, "rat.query-result/v1")
        facts = doc["facts"]
        self.assertIn("success_candidate_count", facts)
        self.assertIn("failure_candidate_count", facts)
        self.assertLessEqual(len(facts.get("success_candidates", [])), facts["success_candidate_count"])
        self.assertLessEqual(len(facts.get("failure_candidates", [])), facts["failure_candidate_count"])
        if facts["success_candidate_count"] or facts["failure_candidate_count"]:
            # budget_bytes=1 forces truncation whenever any candidate exists
            self.assertEqual(doc["status"], "partial")
            self.assertIn("truncated_counts", doc["coverage"]["omitted"])

if __name__ == "__main__":
    unittest.main()
