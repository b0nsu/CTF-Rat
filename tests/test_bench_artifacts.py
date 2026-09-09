import io
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.bench_artifacts import (
    ArtifactMaterializationError, git_blob_sha1, materialize_entry,
)


class BenchArtifactTests(unittest.TestCase):
    def _entry(self, payload):
        return {
            "id": "real-example-01",
            "dir": "bench/artifacts/real-example-01",
            "binary": "chall.bin",
            "fetch": {
                "url": "https://example.invalid/chall.bin",
                "git_blob_sha1": git_blob_sha1(payload),
                "license": "Apache-2.0",
            },
        }

    def test_git_blob_sha1_matches_git_object_format(self):
        self.assertEqual(
            git_blob_sha1(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )

    def test_materialize_downloads_verifies_and_marks_executable(self):
        payload = b"\x7fELF-test-payload"
        entry = self._entry(payload)

        def opener(_request, timeout=None):
            self.assertEqual(timeout, 60)
            return io.BytesIO(payload)

        with tempfile.TemporaryDirectory() as root:
            status = materialize_entry(entry, root=root, opener=opener)
            self.assertEqual(status, "downloaded")
            target = os.path.join(root, entry["dir"], entry["binary"])
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), payload)
            self.assertTrue(os.access(target, os.X_OK))

            def should_not_fetch(*_args, **_kwargs):
                raise AssertionError("verified cached artifact should not hit network")

            self.assertEqual(
                materialize_entry(entry, root=root, opener=should_not_fetch),
                "present",
            )

    def test_mismatched_download_fails_without_installing_file(self):
        payload = b"expected"
        entry = self._entry(payload)

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ArtifactMaterializationError, "digest mismatch"):
                materialize_entry(
                    entry,
                    root=root,
                    opener=lambda *_args, **_kwargs: io.BytesIO(b"tampered"),
                )
            target = os.path.join(root, entry["dir"], entry["binary"])
            self.assertFalse(os.path.exists(target))

    def test_mismatched_existing_file_fails_closed(self):
        payload = b"expected"
        entry = self._entry(payload)

        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, entry["dir"], entry["binary"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(b"wrong")
            with self.assertRaisesRegex(ArtifactMaterializationError, "digest mismatch"):
                materialize_entry(entry, root=root, opener=lambda *_args, **_kwargs: io.BytesIO(payload))
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), b"wrong")


if __name__ == "__main__":
    unittest.main()
