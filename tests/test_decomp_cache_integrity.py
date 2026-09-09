import json
import os
import tempfile
import unittest

from ratlib.decomp_cache import (
    PAYLOAD_SCHEMA,
    SCHEMA,
    load_meta,
    validate,
    write_meta,
)


class DecompPayloadIntegrityTests(unittest.TestCase):
    def fixture(self, root):
        binary = os.path.join(root, "binary")
        with open(binary, "wb") as fh:
            fh.write(b"fixture-binary")

        scripts = os.path.join(root, "scripts")
        os.makedirs(scripts)
        for name in ("DecompExport.java", "DecompOne.java"):
            with open(os.path.join(scripts, name), "w", encoding="utf-8") as fh:
                fh.write("// %s\n" % name)

        ghidra = os.path.join(root, "ghidra")
        os.makedirs(os.path.join(ghidra, "Ghidra"))
        with open(os.path.join(ghidra, "Ghidra", "application.properties"), "w", encoding="utf-8") as fh:
            fh.write("application.version=12.test\n")

        cache = binary + ".decomp"
        os.makedirs(cache)
        with open(os.path.join(cache, "_index.txt"), "w", encoding="utf-8") as fh:
            fh.write("00001000\tmain\t10\t00001000_main\n")
        with open(os.path.join(cache, "00001000_main.c"), "w", encoding="utf-8") as fh:
            fh.write("int main(void) { return 0; }\n")
        return binary, scripts, ghidra, cache

    def seal(self, binary, scripts, ghidra, cache):
        write_meta(cache, binary, ghidra, scripts, "complete")
        self.assertEqual(validate(cache, binary, ghidra, scripts), (True, "hit"))
        return load_meta(cache)

    def test_complete_cache_records_payload_digest(self):
        with tempfile.TemporaryDirectory() as root:
            binary, scripts, ghidra, cache = self.fixture(root)
            meta = self.seal(binary, scripts, ghidra, cache)
            self.assertEqual(meta["schema"], SCHEMA)
            self.assertEqual(meta["payload_schema"], PAYLOAD_SCHEMA)
            self.assertTrue(meta["payload_digest"].startswith("sha256:"))

    def test_modified_c_payload_is_corrupt(self):
        with tempfile.TemporaryDirectory() as root:
            binary, scripts, ghidra, cache = self.fixture(root)
            self.seal(binary, scripts, ghidra, cache)
            with open(os.path.join(cache, "00001000_main.c"), "a", encoding="utf-8") as fh:
                fh.write("// changed\n")
            self.assertEqual(validate(cache, binary, ghidra, scripts), (False, "corrupt"))

    def test_deleted_c_payload_is_corrupt(self):
        with tempfile.TemporaryDirectory() as root:
            binary, scripts, ghidra, cache = self.fixture(root)
            self.seal(binary, scripts, ghidra, cache)
            os.unlink(os.path.join(cache, "00001000_main.c"))
            self.assertEqual(validate(cache, binary, ghidra, scripts), (False, "corrupt"))

    def test_modified_index_is_corrupt(self):
        with tempfile.TemporaryDirectory() as root:
            binary, scripts, ghidra, cache = self.fixture(root)
            self.seal(binary, scripts, ghidra, cache)
            with open(os.path.join(cache, "_index.txt"), "a", encoding="utf-8") as fh:
                fh.write("00002000\thelper\t8\n")
            self.assertEqual(validate(cache, binary, ghidra, scripts), (False, "corrupt"))

    def test_v1_metadata_is_stale_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            binary, scripts, ghidra, cache = self.fixture(root)
            self.seal(binary, scripts, ghidra, cache)
            meta_path = os.path.join(cache, ".rat-cache.json")
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
            meta["schema"] = "rat.decomp-cache/v1"
            meta.pop("payload_schema", None)
            meta.pop("payload_digest", None)
            with open(meta_path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
            self.assertEqual(validate(cache, binary, ghidra, scripts), (False, "stale"))

    def test_one_shot_append_requires_and_allows_reseal(self):
        with tempfile.TemporaryDirectory() as root:
            binary, scripts, ghidra, cache = self.fixture(root)
            self.seal(binary, scripts, ghidra, cache)

            with open(os.path.join(cache, "_index.txt"), "a", encoding="utf-8") as fh:
                fh.write("00002000\thelper\t8\n")
            with open(os.path.join(cache, "helper.c"), "w", encoding="utf-8") as fh:
                fh.write("int helper(void) { return 1; }\n")

            self.assertEqual(validate(cache, binary, ghidra, scripts), (False, "corrupt"))
            write_meta(cache, binary, ghidra, scripts, "complete")
            self.assertEqual(validate(cache, binary, ghidra, scripts), (True, "hit"))
            meta = load_meta(cache)
            self.assertEqual(meta["functions_total"], 2)
            self.assertEqual(meta["functions_exported"], 2)


if __name__ == "__main__":
    unittest.main()
