import copy
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.bench_suite import (
    SuiteValidationError, load_suite, project_suite, suite_digest, validate_suite,
)


class BenchSuiteManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "bench", "suite.json"), encoding="utf-8") as fh:
            cls.suite = json.load(fh)

    def test_committed_suite_validates(self):
        self.assertIs(validate_suite(self.suite), self.suite)
        corpora = {entry["corpus"] for entry in self.suite["entries"]}
        self.assertEqual(corpora, {"synthetic", "real"})
        self.assertTrue(all(entry["redistributable"] is True for entry in self.suite["entries"]))
        real = [entry for entry in self.suite["entries"] if entry["corpus"] == "real"]
        self.assertTrue(real)
        self.assertTrue(all(entry.get("binary") and entry.get("fetch") for entry in real))

    def test_suite_digest_is_stable_and_content_sensitive(self):
        first = suite_digest(self.suite)
        second = suite_digest(copy.deepcopy(self.suite))
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
        changed = copy.deepcopy(self.suite)
        changed["entries"][0]["difficulty"] += 1
        self.assertNotEqual(first, suite_digest(changed))

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
        doc = {"schema": "rat.bench-suite/v2", "entries": [entry]}
        self.assertIs(validate_suite(doc), doc)

    def test_fetch_metadata_requires_pinned_redistributable_binary(self):
        real = copy.deepcopy(next(entry for entry in self.suite["entries"] if entry["corpus"] == "real"))

        bad = copy.deepcopy(real)
        bad["fetch"]["git_blob_sha1"] = "not-a-digest"
        with self.assertRaisesRegex(SuiteValidationError, "git_blob_sha1"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [bad]})

        bad = copy.deepcopy(real)
        bad["fetch"]["url"] = "http://example.invalid/chall"
        with self.assertRaisesRegex(SuiteValidationError, "absolute https URL"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [bad]})

        bad = copy.deepcopy(real)
        bad["redistributable"] = False
        with self.assertRaisesRegex(SuiteValidationError, "redistributable=true"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [bad]})

        bad = copy.deepcopy(real)
        bad.pop("binary")
        with self.assertRaisesRegex(SuiteValidationError, "requires source or binary"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [bad]})

    def test_project_suite_selects_one_corpus_without_mutating_source(self):
        doc = copy.deepcopy(self.suite)
        private = copy.deepcopy(doc["entries"][0])
        private.update({"id": "heldout-stack-01", "corpus": "private", "redistributable": False})
        doc["entries"].append(private)
        projected = project_suite(doc, corpus="private")
        self.assertEqual([entry["id"] for entry in projected["entries"]], ["heldout-stack-01"])
        self.assertEqual(len(doc["entries"]), len(self.suite["entries"]) + 1)

    def test_projected_suite_digest_tracks_exact_execution_set(self):
        doc = copy.deepcopy(self.suite)
        private = copy.deepcopy(doc["entries"][0])
        private.update({"id": "heldout-stack-01", "corpus": "private", "redistributable": False})
        doc["entries"].append(private)
        synthetic = project_suite(doc, corpus="synthetic")
        private_only = project_suite(doc, corpus="private")
        self.assertNotEqual(suite_digest(synthetic), suite_digest(private_only))

    def test_project_suite_rejects_empty_corpus(self):
        with self.assertRaisesRegex(SuiteValidationError, "no entries for corpus: private"):
            project_suite(self.suite, corpus="private")

    def test_flag_regex_entry_requires_a_compilable_pattern(self):
        # R2-6: a flag-regex entry without a usable ``pattern`` would KeyError at
        # run time inside _verify_flag_regex; reject it at load time instead.
        base = copy.deepcopy(next(e for e in self.suite["entries"]
                                  if e["verify"]["kind"] == "flag-regex"))
        missing = copy.deepcopy(base)
        missing["verify"].pop("pattern", None)
        with self.assertRaisesRegex(SuiteValidationError, "pattern is required for flag-regex"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [missing]})
        broken = copy.deepcopy(base)
        broken["verify"]["pattern"] = "FLAG{["  # unbalanced -> re.error
        with self.assertRaisesRegex(SuiteValidationError, "pattern is invalid"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [broken]})

    def test_symsolve_restore_entry_requires_find_str_and_expected(self):
        # R2-6: symsolve-restore reads verify["find_str"]/["expected"] at run time.
        base = copy.deepcopy(self.suite["entries"][0])
        base["verify"] = {"kind": "symsolve-restore", "find_str": "FLAG",
                          "expected": "s3cr3t", "stdin_len": 8}
        good = {"schema": "rat.bench-suite/v2", "entries": [copy.deepcopy(base)]}
        self.assertIs(validate_suite(good), good)
        for field in ("find_str", "expected"):
            bad = copy.deepcopy(base)
            bad["verify"].pop(field)
            with self.subTest(field=field):
                with self.assertRaisesRegex(SuiteValidationError,
                                            "%s is required for symsolve-restore" % field):
                    validate_suite({"schema": "rat.bench-suite/v2", "entries": [bad]})
        bad_len = copy.deepcopy(base)
        bad_len["verify"]["stdin_len"] = 0
        with self.assertRaisesRegex(SuiteValidationError, "stdin_len must be a positive integer"):
            validate_suite({"schema": "rat.bench-suite/v2", "entries": [bad_len]})

    def test_runtime_files_must_be_a_string_list(self):
        # R2-6: a bare string would iterate per-character and _relative_path each
        # char; require an explicit list of strings.
        doc = copy.deepcopy(self.suite)
        doc["entries"][0]["runtime_files"] = "libc.so.6"
        with self.assertRaisesRegex(SuiteValidationError, "runtime_files must be a list of strings"):
            validate_suite(doc)
        doc2 = copy.deepcopy(self.suite)
        doc2["entries"][0]["runtime_files"] = ["ok.bin", 7]
        with self.assertRaisesRegex(SuiteValidationError, "runtime_files must be a list of strings"):
            validate_suite(doc2)

    def test_load_suite_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{bad")
            with self.assertRaisesRegex(SuiteValidationError, "invalid suite JSON"):
                load_suite(path)


if __name__ == "__main__":
    unittest.main()
