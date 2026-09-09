import copy
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from ratlib import run_manifest
from ratlib.state_v2 import Stream


class RunManifestStateProjection(unittest.TestCase):
    def _init(self, root):
        binary = os.path.join(root, "chall")
        with open(binary, "wb") as fh:
            fh.write(b"fixture")
        path = os.path.join(root, "run.json")
        manifest = run_manifest.new_direct("fixture", binary, None, None)
        run_manifest.atomic_write(path, manifest)
        return path

    def test_stale_writer_cannot_regress_latest_event_cursor(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._init(root)
            stream = Stream(root)
            first = stream.append("run.initialized", {"challenge": "fixture"})
            second = stream.append("note.recorded", {"note_id": "n2"})

            current = run_manifest.read(path)
            self.assertEqual(current["state"]["latest_event_cursor"]["seq"], second["seq"])

            stale = copy.deepcopy(current)
            stale["state"] = {
                "stream_id": first["stream_id"],
                "latest_event_cursor": {"stream_id": first["stream_id"], "seq": first["seq"]},
                "latest_checkpoint_id": "stale-checkpoint",
            }
            run_manifest.atomic_write(path, stale)

            final = run_manifest.read(path)
            self.assertEqual(final["state"]["stream_id"], second["stream_id"])
            self.assertEqual(final["state"]["latest_event_cursor"], {
                "stream_id": second["stream_id"], "seq": second["seq"],
            })
            self.assertIsNone(final["state"]["latest_checkpoint_id"])

    def test_checkpoint_pointer_is_rederived_from_state_not_stale_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._init(root)
            stream = Stream(root)
            stream.append("run.initialized", {"challenge": "fixture"})
            checkpoint = stream.checkpoint(
                phase="solve-P0", task_id="local", role="orchestrator", reason="test"
            )
            tail = stream.append("note.recorded", {"note_id": "after-checkpoint"})

            stale = run_manifest.read(path)
            stale["state"] = {
                "stream_id": tail["stream_id"],
                "latest_event_cursor": {"stream_id": tail["stream_id"], "seq": 1},
                "latest_checkpoint_id": None,
            }
            run_manifest.atomic_write(path, stale)

            final = run_manifest.read(path)
            self.assertEqual(final["state"]["latest_event_cursor"]["seq"], tail["seq"])
            self.assertEqual(final["state"]["latest_checkpoint_id"], checkpoint["checkpoint_id"])


if __name__ == "__main__":
    unittest.main()
