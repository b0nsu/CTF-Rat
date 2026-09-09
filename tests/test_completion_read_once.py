import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.completion import completion_gate
from ratlib.state_v2 import Stream


class CompletionReadOnceTests(unittest.TestCase):
    def test_completion_gate_materializes_one_state_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            original = Stream.read
            calls = []

            def counted(instance):
                calls.append(instance.path)
                return original(instance)

            with patch.object(Stream, "read", counted):
                result = completion_gate(root)

            self.assertFalse(result["verified"])
            self.assertEqual(result["reason"], "no-active-primitive")
            self.assertEqual(len(calls), 1, "completion gate must perform one full STATE read")


if __name__ == "__main__":
    unittest.main()
