import os, sqlite3, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.cache import Cache, canonical_key, key as legacy_key
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
            idx_root = os.path.join(os.path.dirname(os.path.abspath(cache)), ".rat")
            entry = Cache(idx_root).get_entry("sha256:" + decomp_cache_key(prov))
            self.assertIsNotNone(entry)
            self.assertEqual(entry["backend"], "decomp_dir")
            self.assertEqual(entry["path"], cache)

    def test_partial_cache_is_not_registered(self):
        with tempfile.TemporaryDirectory() as temp:
            binary, scripts, ghidra, cache = self._fixture(temp)
            write_decomp_meta(cache, binary, ghidra, scripts, "partial", "timeout")
            prov = decomp_provenance(binary, ghidra, scripts)
            idx_root = os.path.join(os.path.dirname(os.path.abspath(cache)), ".rat")
            self.assertIsNone(Cache(idx_root).get_entry("sha256:" + decomp_cache_key(prov)))

if __name__ == "__main__":
    unittest.main()
