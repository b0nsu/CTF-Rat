import os, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.artifact import put_bytes
import ratlib.desktop_api as desktop_api
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

    def test_live_snapshot_parses_state_once(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            stream.append("hypothesis.recorded", {"hypothesis_id": "H1"})
            original_read = Stream.read
            calls = []

            def counted(instance):
                calls.append(instance.path)
                return original_read(instance)

            with patch.object(Stream, "read", counted):
                doc = snapshot(root)
            self.assertEqual(doc["event_count"], 1)
            self.assertEqual(len(calls), 1)

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
            self.assertFalse(first["reset"])
            self.assertFalse(first["unchanged"])
            self.assertIsInstance(first["cursor"].get("source_generation"), str)
            second = event_delta(root, after_seq=first["cursor"]["seq"], limit=2)
            self.assertEqual([event["seq"] for event in second["events"]], [4])
            self.assertFalse(second["has_more"])

    def test_event_delta_unchanged_hint_skips_state_parse(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            stream.append("hypothesis.recorded", {"hypothesis_id": "H1"})
            first = event_delta(root, after_seq=0, limit=10)
            cursor = first["cursor"]
            self.assertIsInstance(cursor["source_generation"], str)
            with patch.object(Stream, "read", side_effect=AssertionError("unchanged poll parsed STATE")):
                unchanged = event_delta(
                    root,
                    after_seq=cursor["seq"],
                    stream_id=cursor["stream_id"],
                    known_generation=cursor["source_generation"],
                    limit=10,
                )
            self.assertTrue(unchanged["unchanged"])
            self.assertFalse(unchanged["reset"])
            self.assertEqual(unchanged["events"], [])
            self.assertEqual(unchanged["cursor"], cursor)

    def test_event_delta_stream_change_resets_sequence_cursor(self):
        with tempfile.TemporaryDirectory() as first_root, tempfile.TemporaryDirectory() as second_root:
            first_stream = Stream(first_root)
            for index in range(3):
                first_stream.append("hypothesis.recorded", {"hypothesis_id": "OLD%d" % index})
            old = event_delta(first_root, after_seq=0, limit=10)

            second_stream = Stream(second_root)
            second_stream.append("hypothesis.recorded", {"hypothesis_id": "NEW"})
            reset = event_delta(
                second_root,
                after_seq=old["cursor"]["seq"],
                stream_id=old["cursor"]["stream_id"],
                limit=10,
            )
            self.assertTrue(reset["reset"])
            self.assertFalse(reset["unchanged"])
            self.assertEqual(reset["after_seq"], 0)
            self.assertEqual([event["seq"] for event in reset["events"]], [1])
            self.assertNotEqual(reset["stream_id"], old["stream_id"])

    def test_event_delta_rejects_unbounded_or_invalid_hint_requests(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                event_delta(root, after_seq=-1)
            with self.assertRaises(ValueError):
                event_delta(root, limit=5001)
            with self.assertRaises(ValueError):
                event_delta(root, known_generation="")

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

    def test_artifact_preview_is_single_pass_and_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            payload = b"A" * (300 * 1024)
            record = put_bytes(
                payload,
                kind="desktop-test",
                media_type="application/octet-stream",
                logical_name="large.bin",
                root=stream.root,
            )
            original_preview = desktop_api.artifact_read_preview
            with patch.object(desktop_api, "artifact_read_preview", wraps=original_preview) as store_preview, patch.object(
                desktop_api,
                "artifact_metadata",
                side_effect=AssertionError("desktop preview performed a second artifact verification"),
            ):
                preview = desktop_api.artifact_preview(root, record["digest"], max_bytes=1024)
            store_preview.assert_called_once()
            self.assertEqual(preview["preview_bytes"], 1024)
            self.assertEqual(preview["total_bytes"], len(payload))
            self.assertTrue(preview["truncated"])
            self.assertEqual(preview["encoding"], "base64")

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
