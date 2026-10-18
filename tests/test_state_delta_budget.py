import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.compact import bounded_delta_bytes
from ratlib.state_v2 import Stream


class BoundedDeltaTests(unittest.TestCase):
    def test_serializer_preserves_legacy_full_array_and_exact_cap(self):
        events = [{"stream_id": "s", "seq": i, "payload": {"text": "한글" * 40}}
                  for i in range(1, 8)]
        full = bounded_delta_bytes(events, 100000)
        self.assertEqual(json.loads(full), events)
        budget = 450
        page = bounded_delta_bytes(events, budget)
        self.assertLessEqual(len(page) + 1, budget)
        doc = json.loads(page)
        self.assertTrue(doc["truncated"])
        self.assertGreater(len(doc["events"]), 0)
        self.assertEqual(doc["events"], events[:len(doc["events"])])
        self.assertEqual(doc["omitted_count"], len(events) - len(doc["events"]))
        self.assertEqual(doc["next_cursor"], {
            "stream_id": "s", "seq": doc["events"][-1]["seq"]})

    def test_too_small_budget_fails_closed(self):
        events = [{"stream_id": "s", "seq": 1, "payload": {"text": "x" * 1000}}]
        for cap in (0, 1, 80):
            with self.subTest(cap=cap), self.assertRaisesRegex(ValueError, "max-bytes"):
                bounded_delta_bytes(events, cap)

    def run_state(self, root, *args):
        env = dict(os.environ, CTF_HOME=str(ROOT), PYTHONPATH=str(ROOT / "bin"))
        return subprocess.run(
            [sys.executable, str(ROOT / "bin" / "state"), "--dir", root, *args],
            text=True, capture_output=True, env=env, timeout=15)

    def test_cli_pages_every_event_in_order_using_next_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = Stream(directory)
            for i in range(25):
                stream.append("unknown.recorded", {
                    "unknown_id": f"u{i}", "text": "한글" + ("x" * 90)})
            full_result = self.run_state(directory, "delta", "--max-bytes", "100000")
            self.assertEqual(full_result.returncode, 0, full_result.stderr)
            expected = json.loads(full_result.stdout)
            self.assertEqual(len(expected), 25)

            budget = 1200
            seen = []
            cursor = None
            for _ in range(30):
                argv = ["delta", "--max-bytes", str(budget)]
                if cursor is not None:
                    argv.extend(["--after", json.dumps(cursor, separators=(",", ":"))])
                result = self.run_state(directory, *argv)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertLessEqual(len(result.stdout.encode()), budget)
                payload = json.loads(result.stdout)
                if isinstance(payload, list):
                    seen.extend(payload)
                    break
                self.assertTrue(payload["truncated"])
                self.assertGreater(len(payload["events"]), 0)
                self.assertEqual(payload["omitted_count"],
                                 len(expected) - len(seen) - len(payload["events"]))
                seen.extend(payload["events"])
                next_cursor = payload["next_cursor"]
                self.assertEqual(next_cursor["seq"], seen[-1]["seq"])
                self.assertTrue(cursor is None or next_cursor["seq"] > cursor["seq"])
                cursor = next_cursor
            else:
                self.fail("delta pagination failed to converge")

            self.assertEqual(seen, expected)

    def test_cli_does_not_emit_oversized_event_when_budget_is_too_small(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = Stream(directory)
            stream.append("unknown.recorded", {
                "unknown_id": "oversized", "text": "y" * 1000})
            result = self.run_state(directory, "delta", "--max-bytes", "80")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertIn("max-bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()
