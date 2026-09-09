import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.route import route


def revq(strings):
    return {
        "imports": ["read", "puts"],
        "evasion": [],
        "functions": [{"name": "main", "calls": ["read", "puts"], "strings": list(strings)}],
        "strings": [{"val": value} for value in strings],
    }


class StructuredCheckerShape(unittest.TestCase):
    def test_success_failure_pair_selects_checker_without_hard_commit(self):
        result = route(
            revq=revq(["Correct: FLAG{fixture}", "Wrong"]),
            interesting=[{"func": "main", "score": 8, "why": ["display-only"]}],
        )
        self.assertEqual(result["subroute"], "rev-checker")
        self.assertEqual(result["commitment"], "provisional")
        self.assertIsNone(result["skill"])
        oracle = [signal for signal in result["signals"] if signal["kind"] == "checker-oracle-strings"]
        self.assertEqual(len(oracle), 1)
        self.assertEqual(oracle[0]["quality"], "heuristic")
        self.assertEqual(oracle[0]["value"]["success_count"], 1)
        self.assertEqual(oracle[0]["value"]["failure_count"], 1)

    def test_one_sided_result_string_is_not_checker_shape(self):
        result = route(
            revq=revq(["Correct: FLAG{fixture}"]),
            interesting=[{"func": "main", "score": 8, "why": ["비교함수 호출: memcmp"]}],
        )
        self.assertEqual(result["subroute"], "rev-symbolic")
        self.assertFalse(any(signal["kind"] == "checker-oracle-strings" for signal in result["signals"]))


if __name__ == "__main__":
    unittest.main()
