import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib import orchestration
from ratlib.state_v2 import Stream


class StateReadOnceTests(unittest.TestCase):
    def test_verify_records_scans_state_once(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            stream.append("verification.recorded", {"verification_id": "verify_old"})
            stream.append("verification.staled", {"verification_id": "verify_old"})
            stream.append("verification.recorded", {"verification_id": "verify_live", "lineage_id": "lineage_1"})

            original = Stream.read
            calls = []

            def counted(instance):
                calls.append(instance.path)
                return original(instance)

            with patch.object(Stream, "read", counted):
                records = orchestration._verify_records(root, "lineage_1")

            self.assertEqual([record["verification_id"] for record in records], ["verify_live"])
            self.assertEqual(len(calls), 1, "verification projection must perform one full STATE read")


if __name__ == "__main__":
    unittest.main()
