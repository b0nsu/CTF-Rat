import os, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

import ratlib.artifact as artifact


class ArtifactDescribeTests(unittest.TestCase):
    def object_path(self, root, digest):
        value = digest.removeprefix("sha256:")
        return os.path.join(root, "objects", "sha256", value[:2], value[2:])

    def test_describe_validates_metadata_and_size_without_hashing_contents(self):
        with tempfile.TemporaryDirectory() as root:
            record = artifact.put_bytes(
                b"A" * (1024 * 1024),
                kind="test",
                media_type="application/octet-stream",
                logical_name="large.bin",
                root=root,
            )
            with patch.object(
                artifact,
                "_checked_prefix",
                side_effect=AssertionError("describe hashed object contents"),
            ):
                described = artifact.describe(record["digest"], root=root)
            self.assertEqual(described, record)

    def test_describe_rejects_missing_object(self):
        with tempfile.TemporaryDirectory() as root:
            record = artifact.put_bytes(
                b"hello",
                kind="test",
                media_type="text/plain",
                logical_name="hello.txt",
                root=root,
            )
            os.unlink(self.object_path(root, record["digest"]))
            with self.assertRaises(RuntimeError):
                artifact.describe(record["digest"], root=root)

    def test_metadata_still_hash_verifies_same_size_corruption(self):
        with tempfile.TemporaryDirectory() as root:
            record = artifact.put_bytes(
                b"hello",
                kind="test",
                media_type="text/plain",
                logical_name="hello.txt",
                root=root,
            )
            with open(self.object_path(root, record["digest"]), "wb") as out:
                out.write(b"jello")
            described = artifact.describe(record["digest"], root=root)
            self.assertEqual(described["size"], 5)
            with self.assertRaises(RuntimeError):
                artifact.metadata(record["digest"], root=root)


if __name__ == "__main__":
    unittest.main()
