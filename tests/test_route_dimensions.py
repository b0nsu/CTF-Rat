import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.route import route
from ratlib.schema import validate


def profile(imports=(), facts=()):
    return {
        "imports": list(imports),
        "facts": [{"kind": kind, "value": value} for kind, value in facts],
    }


def revq(imports=()):
    return {"imports": list(imports), "evasion": [], "functions": [], "strings": []}


class RouteConflictDimensions(unittest.TestCase):
    def test_pwn_sibling_conflict_projects_every_surface(self):
        r = route(profile=profile(
            imports=["malloc", "free", "printf", "read", "gets"],
            facts=[("elf.nx", True)],
        ))

        self.assertEqual(r["subroute"], "pwn-heap")
        self.assertTrue(r["conflict"])
        self.assertEqual(r["commitment"], "provisional")
        self.assertIsNone(r["skill"])
        self.assertEqual(
            r["dimensions"]["vulnerability_surfaces"],
            ["heap-lifetime-candidate", "format-string-candidate", "stack-overwrite-candidate"],
        )
        self.assertEqual(r["dimensions"]["constraints"], ["nx"])
        self.assertTrue(any("allocator imports" in item for item in r["unresolved"]))
        self.assertTrue(any("format argument" in item for item in r["unresolved"]))
        self.assertTrue(any("PC-control" in item for item in r["unresolved"]))
        validate(r, "rat.route-result/v1")

    def test_rev_primary_conflict_keeps_pwn_surface_visible(self):
        r = route(
            profile=profile(imports=["printf", "read"]),
            revq=revq(imports=["printf", "read", "memcmp"]),
            interesting=[{
                "func": "check_flag",
                "score": 8,
                "why": ["비교함수 호출: memcmp"],
            }],
        )

        self.assertEqual(r["subroute"], "rev-checker")
        self.assertTrue(r["conflict"])
        self.assertEqual(r["commitment"], "provisional")
        self.assertIsNone(r["skill"])
        self.assertEqual(r["dimensions"]["program_shapes"], ["checker"])
        self.assertEqual(r["dimensions"]["vulnerability_surfaces"], ["format-string-candidate"])
        self.assertTrue(any("checker semantics" in item for item in r["unresolved"]))
        self.assertTrue(any("format argument" in item for item in r["unresolved"]))
        validate(r, "rat.route-result/v1")

    def test_pwn_primary_conflict_keeps_rev_shape_visible(self):
        r = route(
            profile=profile(imports=["malloc", "free"]),
            revq=revq(imports=["malloc", "free", "memcmp"]),
            interesting=[{
                "func": "maybe_success",
                "score": 3,
                "why": ["문자열 상수 비교 대상"],
            }],
        )

        self.assertEqual(r["subroute"], "pwn-heap")
        self.assertTrue(r["conflict"])
        self.assertEqual(r["dimensions"]["vulnerability_surfaces"], ["heap-lifetime-candidate"])
        self.assertEqual(r["dimensions"]["program_shapes"], ["symbolic-candidate"])
        self.assertEqual(r["unresolved"][0],
                         "multiple plausible routes remain; run one cheap discriminating probe before loading a route-specific skill")
        validate(r, "rat.route-result/v1")


if __name__ == "__main__":
    unittest.main()
