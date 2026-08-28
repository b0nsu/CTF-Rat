import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.route import route


def revq(imports=(), functions=(), strings=()):
    return {
        "imports": list(imports),
        "evasion": [],
        "functions": list(functions),
        "strings": [{"val": value} for value in strings],
    }


class CanonicalRouteNextTests(unittest.TestCase):
    def test_checker_uses_front_door_function_query(self):
        result = route(
            revq=revq(imports=["memcmp"]),
            interesting=[{"func": "check_flag", "score": 8,
                          "why": ["비교함수 호출: memcmp"]}],
        )
        self.assertEqual(result["subroute"], "rev-checker")
        self.assertEqual(result["next"], [
            {"query": "rat query func", "target": "check_flag"},
        ])

    def test_symbolic_candidate_resolves_oracle_before_symbolic_execution(self):
        result = route(
            revq=revq(imports=["memcmp"]),
            interesting=[{"func": "transform", "score": 3,
                          "why": ["문자열 상수 비교 대상"]}],
        )
        self.assertEqual(result["subroute"], "rev-symbolic")
        self.assertEqual(result["next"], [
            {"query": "rat query oracle", "target": "success-failure-oracle-before-symbolic"},
        ])

    def test_unknown_keeps_explicit_extra_triage_fallback(self):
        result = route(revq=revq())
        self.assertEqual(result["subroute"], "unknown")
        self.assertEqual(result["next"], [
            {"query": "revq/recon", "target": "more-signal-before-routing"},
        ])


if __name__ == "__main__":
    unittest.main()
