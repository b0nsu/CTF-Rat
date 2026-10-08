import os
import sys
import unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
sys.path.insert(0, BIN)

from ratlib.schema import ValidationError, validate


def query(status="ok", complete=True):
    return {
        "schema": "rat.query-result/v1",
        "query": "slice",
        "status": status,
        "facts": {},
        "heuristics": {},
        "artifacts": [],
        "coverage": {"complete": complete, "scope": "slice", "omitted": None},
        "diagnostics": [],
        "provenance": {"cache": {"hit": False}},
    }


class QuerySchemaTruthTests(unittest.TestCase):
    def test_partial_complete_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate(query(status="partial", complete=True))

    def test_error_complete_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate(query(status="error", complete=True))

    def test_ok_complete_is_valid(self):
        validate(query(status="ok", complete=True))

    def test_partial_incomplete_is_valid(self):
        validate(query(status="partial", complete=False))

    def test_complete_must_be_boolean(self):
        with self.assertRaises(ValidationError):
            validate(query(status="ok", complete=1))


if __name__ == "__main__":
    unittest.main()
