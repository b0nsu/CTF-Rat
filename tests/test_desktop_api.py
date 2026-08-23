import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.artifact import put_bytes
from ratlib.desktop_api import artifact_preview, event_delta, list_artifacts, snapshot, telemetry
from ratlib.state_v2 import Stream


class DesktopApiTests(unittest.TestCase):
    def test_snapshot_materializes_existing_state(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            stream.append("hypothesis.recorded", {"hypothesis_id": "H1", "text": "checker uses memcmp"})
            stream.append("next.recorded", {"probe": "inspect transform"})
            doc = snapshot(root)
            self.assertEqual(doc["schema"], "rat.desktop.snapshot/v1")
            self.assertEqual(doc["cursor"]["seq"], 2)
            self.assertEqual(doc["event_count"], 2)
            self.assertEqual(doc["total_event_count"], 2)
            self.assertFalse(doc["historical"])
            self.assertIn("H1", doc["view"]["hypotheses"])
            self.assertEqual(doc["view"]["next_probes"][-1]["probe"], "inspect transform")

    def test_snapshot_can_replay_historical_state(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            stream.append("hypothesis.recorded", {"hypothesis_id": "H1", "text": "first"})
            stream.append("hypothesis.recorded", {"hypothesis_id": "H2", "text": "second"})
            replay = snapshot(root, until_seq=1)
            self.assertTrue(replay["historical"])
            self.assertEqual(replay["cursor"]["seq"], 1)
            self.assertEqual(replay["event_count"], 1)
            self.assertEqual(replay["total_event_count"], 2)
            self.assertIn("H1", replay["view"]["hypotheses"])
            self.assertNotIn("H2", replay["view"]["hypotheses"])

    def test_event_delta_is_ordered_and_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            for index in range(1, 5):
                stream.append("hypothesis.recorded", {"hypothesis_id": "H%d" % index})
            first = event_delta(root, after_seq=1, limit=2)
            self.assertEqual([event["seq"] for event in first["events"]], [2, 3])
            self.assertTrue(first["has_more"])
            second = event_delta(root, after_seq=first["cursor"]["seq"], limit=2)
            self.assertEqual([event["seq"] for event in second["events"]], [4])
            self.assertFalse(second["has_more"])

    def test_event_delta_rejects_unbounded_requests(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                event_delta(root, after_seq=-1)
            with self.assertRaises(ValueError):
                event_delta(root, limit=5001)

    def test_artifact_list_and_preview_reuse_canonical_store(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            record = put_bytes(
                b'{"answer":42}',
                kind="desktop-test",
                media_type="application/json",
                logical_name="answer.json",
                root=stream.root,
                provenance={"producer": "test"},
            )
            listing = list_artifacts(root)
            self.assertEqual(listing["total"], 1)
            self.assertEqual(listing["artifacts"][0]["digest"], record["digest"])
            preview = artifact_preview(root, record["digest"], max_bytes=64)
            self.assertEqual(preview["encoding"], "utf-8")
            self.assertEqual(preview["content"], '{"answer":42}')
            self.assertFalse(preview["truncated"])

    def test_telemetry_counts_existing_event_types(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            stream.append("hypothesis.recorded", {"hypothesis_id": "H1"})
            stream.append("next.recorded", {"probe": "x"})
            doc = telemetry(root)
            self.assertEqual(doc["event_count"], 2)
            self.assertEqual(doc["event_types"]["hypothesis.recorded"], 1)
            self.assertEqual(doc["groups"]["hypothesis"], 1)


if __name__ == "__main__":
    unittest.main()
