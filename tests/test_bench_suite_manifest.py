import copy
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.bench_suite import SuiteValidationError, load_suite, project_suite, validate_suite


class BenchSuiteManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "bench", "suite.json"), encoding="utf-8") as fh:
            cls.suite = json.load(fh)

    def test_committed_suite_validates(self):
        self.assertIs(validate_suite(self.suite), self.suite)
        self.assertTrue(all(entry["corpus"] == "synthetic" for entry in self.suite["entries"]))
        self.assertTrue(all(entry["redistributable"] is True for entry in self.suite["entries"]))

    def test_duplicate_id_is_rejected(self):
        doc = copy.deepcopy(self.suite)
        doc["entries"].append(copy.deepcopy(doc["entries"][0]))
        with self.assertRaisesRegex(SuiteValidationError, "duplicate benchmark entry id"):
            validate_suite(doc)

    def test_path_escape_is_rejected(self):
        doc = copy.deepcopy(self.suite)
        doc["entries"][0]["dir"] = "../outside"
        with self.assertRaisesRegex(SuiteValidationError, "escapes the suite root"):
            validate_suite(doc)

    def test_missing_corpus_metadata_is_rejected(self):
        doc = copy.deepcopy(self.suite)
        del doc["entries"][0]["corpus"]
        with self.assertRaisesRegex(SuiteValidationError, "corpus must be one of"):
            validate_suite(doc)

    def test_invalid_or_duplicate_capability_is_rejected(self):
        for capabilities in (["Stack Overflow"], ["stack-overflow", "stack-overflow"]):
            with self.subTest(capabilities=capabilities):
                doc = copy.deepcopy(self.suite)
                doc["entries"][0]["capabilities"] = capabilities
                with self.assertRaisesRegex(SuiteValidationError, "capabilities"):
                    validate_suite(doc)

    def test_real_binary_manifest_can_remain_non_redistributable(self):
        entry = copy.deepcopy(self.suite["entries"][0])
        entry.update({
            "id": "heldout-stack-01",
            "corpus": "private",
            "capabilities": ["stack-overflow", "libc-sensitive"],
            "redistributable": False,
            "binary": "chall.bin",
        })
        entry.pop("source", None)
        doc = {"schema": "rat.bench-suite/v1", "entries": [entry]}
        self.assertIs(validate_suite(doc), doc)

    def test_project_suite_selects_one_corpus_without_mutating_source(self):
        doc = copy.deepcopy(self.suite)
        private = copy.deepcopy(doc["entries"][0])
        private.update({"id": "heldout-stack-01", "corpus": "private", "redistributable": False})
        doc["entries"].append(private)
        projected = project_suite(doc, corpus="private")
        self.assertEqual([entry["id"] for entry in projected["entries"]], ["heldout-stack-01"])
        self.assertEqual(len(doc["entries"]), len(self.suite["entries"]) + 1)

    def test_project_suite_rejects_empty_corpus(self):
        with self.assertRaisesRegex(SuiteValidationError, "no entries for corpus: private"):
            project_suite(self.suite, corpus="private")

    def test_load_suite_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{bad")
            with self.assertRaisesRegex(SuiteValidationError, "invalid suite JSON"):
                load_suite(path)


if __name__ == "__main__":
    unittest.main()
