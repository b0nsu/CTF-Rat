import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from ratlib import artifact


class ArtifactGcReachability(unittest.TestCase):
    def _put(self, root, data, kind="test"):
        if not isinstance(data, bytes):
            data = json.dumps(data, sort_keys=True).encode()
        return artifact.put_bytes(
            data,
            kind=kind,
            media_type="application/json" if data.startswith(b"{") else "application/octet-stream",
            logical_name=kind + ".bin",
            root=root,
        )

    def test_gc_preserves_transitive_nested_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = os.path.join(tmp, ".rat")
            child = self._put(store, b"measured stdout", "stdout")
            middle = self._put(store, {
                "schema": "rat.tool-result/v1",
                "artifacts": [{"kind": "stdout", "digest": child["digest"]}],
            }, "tool-result")
            outer = self._put(store, {
                "schema": "rat.wrapper/v1",
                "result_digest": middle["digest"],
            }, "wrapper")
            orphan = self._put(store, b"unreferenced", "orphan")

            events = os.path.join(store, "events")
            os.makedirs(events, exist_ok=True)
            with open(os.path.join(events, "STATE.v2.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"artifact": outer["digest"]}) + "\n")

            keep = artifact.reachable(store)
            self.assertIn(outer["digest"], keep)
            self.assertIn(middle["digest"], keep)
            self.assertIn(child["digest"], keep)
            self.assertNotIn(orphan["digest"], keep)

            dry = set(artifact.gc(root=store, dry_run=True))
            self.assertEqual(dry, {orphan["digest"]})
            removed = set(artifact.gc(root=store, dry_run=False))
            self.assertEqual(removed, {orphan["digest"]})
            self.assertEqual(artifact.get(outer["digest"], root=store), json.dumps({
                "schema": "rat.wrapper/v1",
                "result_digest": middle["digest"],
            }, sort_keys=True).encode())
            self.assertEqual(artifact.get(middle["digest"], root=store), json.dumps({
                "schema": "rat.tool-result/v1",
                "artifacts": [{"kind": "stdout", "digest": child["digest"]}],
            }, sort_keys=True).encode())
            self.assertEqual(artifact.get(child["digest"], root=store), b"measured stdout")
            with self.assertRaises(FileNotFoundError):
                artifact.get(orphan["digest"], root=store)

    def test_digest_reference_split_across_scan_chunks_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = "sha256:" + "a" * 64
            path = os.path.join(tmp, "control.bin")
            with open(path, "wb") as fh:
                fh.write(("prefix-" + target + "-suffix").encode())
            with patch.object(artifact, "_SCAN_CHUNK_BYTES", 11):
                self.assertEqual(artifact._file_references(path), {target})


if __name__ == "__main__":
    unittest.main()
