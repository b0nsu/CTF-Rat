import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.desktop_api import event_delta, snapshot
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
            self.assertIn("H1", doc["view"]["hypotheses"])
            self.assertEqual(doc["view"]["next_probes"][-1]["probe"], "inspect transform")

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


if __name__ == "__main__":
    unittest.main()
