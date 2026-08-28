import os
import sys
import unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
sys.path.insert(0, BIN)

from ratlib import metrics


class MetricTruthTests(unittest.TestCase):
    def test_v1_time_to_flag_keeps_primitive_pass_semantics(self):
        result = metrics.aggregate(
            [], guard_started_at=1000, primitive_pass_at=1030, verified_solve_at=1090
        )
        self.assertEqual(result["time_to_first_valid_primitive_sec"], 30)
        self.assertEqual(result["time_to_verified_solve_sec"], 90)
        self.assertEqual(result["time_to_flag_sec"], 30)

    def test_old_verify_pass_parameter_is_primitive_pass_alias(self):
        result = metrics.aggregate([], guard_started_at=1000, verify_pass_at=1030)
        self.assertEqual(result["time_to_first_valid_primitive_sec"], 30)
        self.assertEqual(result["time_to_flag_sec"], 30)
        self.assertIsNone(result["time_to_verified_solve_sec"])

    def test_earliest_active_verification_sets_verified_solve_latency(self):
        events = [
            {"type": "verification.recorded", "at": "1970-01-01T00:18:10+00:00",
             "payload": {"verification_id": "verify_first"}},
            {"type": "verification.recorded", "at": "1970-01-01T00:19:10+00:00",
             "payload": {"verification_id": "verify_later"}},
        ]
        with mock.patch.object(metrics, "Stream") as stream_cls, \
             mock.patch.object(metrics, "completion_gate", return_value={"verified": True}) as gate:
            stream_cls.return_value.read.return_value = events
            self.assertEqual(metrics.first_verified_solve_ts("/tmp/chal"), 1090)
        gate.assert_called_once_with("/tmp/chal", verification_id="verify_first")


if __name__ == "__main__":
    unittest.main()
