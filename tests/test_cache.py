import argparse, os, sqlite3, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.cache import Cache, canonical_key, key as legacy_key, resolve_index_root
from ratlib.decomp_cache import cache_key as decomp_cache_key, provenance as decomp_provenance, write_meta as write_decomp_meta

def ck(**overrides):
    base = dict(binary_sha256="sha256:" + "a" * 64, tool_name="revq", tool_version="2",
                params={"engine": "angr"}, dep_versions={"angr": "9.2.213"})
    base.update(overrides)
    return canonical_key(**base)

class CanonicalKeyV2(unittest.TestCase):
    def test_identical_inputs_produce_identical_key(self):
        self.assertEqual(ck(), ck())

    def test_tool_version_change_produces_different_key(self):
        self.assertNotEqual(ck(), ck(tool_version="3"))

    def test_param_dict_key_order_does_not_matter(self):
        a = canonical_key(binary_sha256="sha256:" + "a" * 64, tool_name="revq", tool_version="2",
                           params={"engine": "angr", "fast": False}, dep_versions={})
        b = canonical_key(binary_sha256="sha256:" + "a" * 64, tool_name="revq", tool_version="2",
                           params={"fast": False, "engine": "angr"}, dep_versions={})
        self.assertEqual(a, b)

    def test_artifact_inputs_order_does_not_matter(self):
        a = ck(artifact_inputs=[{"role": "x", "digest": "d1"}, {"role": "y", "digest": "d2"}])
        b = ck(artifact_inputs=[{"role": "y", "digest": "d2"}, {"role": "x", "digest": "d1"}])
        self.assertEqual(a, b)

    def test_different_binary_produces_different_key(self):
        self.assertNotEqual(ck(), ck(binary_sha256="sha256:" + "b" * 64))

    def test_output_schema_and_analysis_schema_version_are_part_of_the_key(self):
        self.assertNotEqual(ck(), ck(output_schema="rat.tool-result/v2"))
        self.assertNotEqual(ck(), ck(analysis_schema_version="v2"))

class CacheEntryIndex(unittest.TestCase):
    def test_get_entry_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            c = Cache(d)
            k = ck()
            self.assertIsNone(c.get_entry(k))
            c.put_entry(k, backend="revq_json", path="/tmp/x.revq.json")
            entry = c.get_entry(k)
            self.assertEqual(entry["backend"], "revq_json")
            self.assertEqual(entry["path"], "/tmp/x.revq.json")
            self.assertIsNone(entry["envelope_digest"])

    def test_put_entry_overwrites_on_same_key(self):
        with tempfile.TemporaryDirectory() as d:
            c = Cache(d); k = ck()
            c.put_entry(k, backend="revq_json", path="/tmp/old.json")
            c.put_entry(k, backend="revq_json", path="/tmp/new.json")
            self.assertEqual(c.get_entry(k)["path"], "/tmp/new.json")

    def test_legacy_get_put_still_work_after_schema_upgrade(self):
        with tempfile.TemporaryDirectory() as d:
            c = Cache(d); k = legacy_key(tool={"name": "x", "version": "1", "build_digest": "sha256:" + "0" * 64},
                                          inputs=[], parameters={}, dependencies={}, policy_digest="sha256:" + "0" * 64)
            self.assertIsNone(c.get(k))
            c.put(k, "sha256:" + "1" * 64)
            self.assertEqual(c.get(k), "sha256:" + "1" * 64)
            self.assertIsNone(c.get_entry(k))

    def test_pre_existing_two_column_database_migrates_in_place(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "indexes", "cache.sqlite3")
            os.makedirs(os.path.dirname(path))
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE cache (key TEXT PRIMARY KEY, envelope_digest TEXT NOT NULL)")
            db.execute("INSERT INTO cache VALUES (?, ?)", ("legacy-key", "sha256:" + "2" * 64))
            db.commit(); db.close()

            c = Cache(d)
            self.assertEqual(c.get("legacy-key"), "sha256:" + "2" * 64)
            self.assertIsNone(c.get_entry("legacy-key"))
            k = ck()
            c.put_entry(k, backend="revq_json", path="/tmp/x.revq.json")
            self.assertEqual(c.get_entry(k)["backend"], "revq_json")

class DecompCacheIndexRegistration(unittest.TestCase):
    def _fixture(self, temp):
        binary = os.path.join(temp, "binary")
        with open(binary, "wb") as f: f.write(b"content")
        scripts = os.path.join(temp, "scripts"); os.makedirs(scripts)
        for name in ("DecompExport.java", "DecompOne.java"):
            with open(os.path.join(scripts, name), "w") as f: f.write(name)
        ghidra = os.path.join(temp, "ghidra")
        os.makedirs(os.path.join(ghidra, "Ghidra"))
        with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as f:
            f.write("application.version=11.test\n")
        cache = binary + ".decomp"; os.makedirs(cache)
        with open(os.path.join(cache, "_index.txt"), "w") as f: f.write("1000\tmain\t10\n")
        return binary, scripts, ghidra, cache

    def test_write_meta_registers_completed_cache_in_canonical_index(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self._fixture(temp)
            write_decomp_meta(cache, binary, ghidra, scripts, "complete")
            prov = decomp_provenance(binary, ghidra, scripts)
            idx_root = resolve_index_root(binary)
            entry = Cache(idx_root).get_entry("sha256:" + decomp_cache_key(prov))
            self.assertIsNotNone(entry)
            self.assertEqual(entry["backend"], "decomp_dir")
            self.assertEqual(entry["path"], cache)

    def test_partial_cache_is_not_registered(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self._fixture(temp)
            write_decomp_meta(cache, binary, ghidra, scripts, "partial", "timeout")
            prov = decomp_provenance(binary, ghidra, scripts)
            idx_root = resolve_index_root(binary)
            self.assertIsNone(Cache(idx_root).get_entry("sha256:" + decomp_cache_key(prov)))

class ResolveIndexRoot(unittest.TestCase):
    def test_override_arg_wins(self):
        self.assertEqual(resolve_index_root("/bin/ls", override="/tmp/idx"), os.path.abspath("/tmp/idx"))

    def test_env_override_used_when_no_arg(self):
        old = os.environ.get("RAT_INDEX_ROOT")
        os.environ["RAT_INDEX_ROOT"] = "/tmp/envidx"
        try:
            self.assertEqual(resolve_index_root("/bin/ls"), os.path.abspath("/tmp/envidx"))
        finally:
            if old is None: os.environ.pop("RAT_INDEX_ROOT", None)
            else: os.environ["RAT_INDEX_ROOT"] = old

    def test_default_anchors_to_binary_dir_regardless_of_cwd(self):
        with tempfile.TemporaryDirectory() as temp:
            sub = os.path.join(temp, "dist"); os.makedirs(sub)
            binary = os.path.join(sub, "chal")
            with open(binary, "wb") as f: f.write(b"x")
            expected = os.path.join(os.path.dirname(os.path.realpath(binary)), ".rat")
            cwd0 = os.getcwd()
            try:
                for where in (temp, sub, cwd0):
                    os.chdir(where)
                    self.assertEqual(resolve_index_root(binary), expected)
            finally:
                os.chdir(cwd0)

class ThreeToolsShareOneIndex(unittest.TestCase):
    """The M2 contract: one sqlite index points at all three backends.

    Regression guard for the index-root divergence rework -- shakes the
    coordinates (binary in a subdir, run from elsewhere) and asserts a single
    shared index carrying revq/decomp/rat-profile entries.
    """
    def _decomp_fixture(self, binary):
        temp = os.path.dirname(binary)
        scripts = os.path.join(temp, "scripts"); os.makedirs(scripts)
        for name in ("DecompExport.java", "DecompOne.java"):
            with open(os.path.join(scripts, name), "w") as f: f.write(name)
        ghidra = os.path.join(temp, "ghidra"); os.makedirs(os.path.join(ghidra, "Ghidra"))
        with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w") as f:
            f.write("application.version=11.test\n")
        cache = binary + ".decomp"; os.makedirs(cache)
        with open(os.path.join(cache, "_index.txt"), "w") as f: f.write("1000\tmain\t10\n")
        return scripts, ghidra, cache

    def test_three_tools_share_one_index(self):
        with tempfile.TemporaryDirectory() as temp:
            sub = os.path.join(temp, "dist"); os.makedirs(sub)
            binary = os.path.join(sub, "chal")
            with open(binary, "wb") as f: f.write(b"content")
            expected = resolve_index_root(binary)

            # rat-profile's analysis.root() (no --store) must land in the same place.
            from ratlib import analysis
            ns = argparse.Namespace(binary=binary, store=None)
            self.assertEqual(os.path.abspath(analysis.root(ns, binary)), os.path.abspath(expected))

            # decomp: real registration path (internally resolves off the binary).
            scripts, ghidra, cache = self._decomp_fixture(binary)
            write_decomp_meta(cache, binary, ghidra, scripts, "complete")
            decomp_key = "sha256:" + decomp_cache_key(decomp_provenance(binary, ghidra, scripts))

            # revq + rat-profile register into the resolved shared index.
            idx = Cache(expected)
            revq_key = ck(tool_name="revq")
            profile_key = ck(tool_name="rat-profile", params={"artifact": "profile"})
            idx.put_entry(revq_key, backend="revq_json", path=binary + ".revq.json")
            idx.put_entry(profile_key, backend="profile_artifact", path="sha256:" + "c" * 64)

            # exactly ONE sqlite exists anywhere under the challenge tree.
            # (os.walk, not glob: the index lives in a dotdir `.rat`, which glob
            # skips, and realpath() normalizes the macOS /var -> /private/var link.)
            sqlites = [os.path.join(dp, "cache.sqlite3")
                       for dp, _, fs in os.walk(os.path.realpath(temp))
                       if "cache.sqlite3" in fs and os.path.basename(dp) == "indexes"]
            self.assertEqual(len(sqlites), 1, "expected one shared index, found: %s" % sqlites)

            # and that one index carries all three backends.
            backends = {idx.get_entry(k)["backend"] for k in (revq_key, decomp_key, profile_key)}
            self.assertEqual(backends, {"revq_json", "decomp_dir", "profile_artifact"})

    def test_source_invocation_roundtrips_on_entry(self):
        with tempfile.TemporaryDirectory() as d:
            c = Cache(d); k = ck()
            c.put_entry(k, backend="profile_artifact", path="sha256:" + "d" * 64, source_invocation="invoke_abc")
            self.assertEqual(c.get_entry(k)["source_invocation"], "invoke_abc")

if __name__ == "__main__":
    unittest.main()
