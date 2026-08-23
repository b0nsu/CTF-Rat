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
        self.assertEqual(doc["schema"], "rat.route-result/v1")

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

class DynVerifyStateCompactPassthrough(unittest.TestCase):
    """Pure argv-forwarding -- exercised against a legacy CLI's own usage/
    error path so no analysis engine is required."""
    def test_state_compact_forwards_to_legacy_state_tool(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, err = run_rat("state", "compact", "--budget-tokens", "500", cwd=d)
            self.assertEqual(code, 0, err)
            doc = json.loads(out)
            self.assertEqual(set(doc), {"invalidating_findings", "confirmed_findings", "pass_primitives",
                                         "hypotheses", "next_probes", "ruled_out", "truncated", "omitted_counts", "cursor"})

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

if __name__ == "__main__":
    unittest.main()
