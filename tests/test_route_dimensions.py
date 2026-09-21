import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.evasion import SIGNAL_SCHEMA as EVASION_SIGNAL_SCHEMA
from ratlib.route import route
from ratlib.schema import validate


def profile(imports=(), facts=()):
    return {
        "imports": list(imports),
        "facts": [{"kind": kind, "value": value} for kind, value in facts],
    }


def revq(imports=(), functions=()):
    return {"imports": list(imports), "evasion": [], "functions": list(functions), "strings": []}


class RouteConflictDimensions(unittest.TestCase):
    def test_pwn_sibling_leads_project_every_surface_without_false_conflict(self):
        r = route(profile=profile(
            imports=["malloc", "free", "printf", "read", "gets"],
            facts=[("elf.nx", True)],
        ))

        self.assertEqual(r["subroute"], "pwn-heap")
        self.assertFalse(r.get("conflict", False))
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

    def test_rev_primary_keeps_nonexclusive_pwn_surface_visible(self):
        r = route(
            profile=profile(imports=["printf", "read"]),
            revq=revq(imports=["printf", "read", "memcmp"],
                      functions=[{"name": "check_flag", "calls": ["memcmp"]}]),
            interesting=[{
                "func": "check_flag",
                "score": 8,
                "why": ["display-only"],
            }],
        )

        self.assertEqual(r["subroute"], "rev-checker")
        self.assertFalse(r.get("conflict", False))
        self.assertEqual(r["commitment"], "provisional")
        self.assertIsNone(r["skill"])
        self.assertEqual(r["dimensions"]["program_shapes"], ["checker"])
        self.assertIn("format-string-candidate", r["dimensions"]["vulnerability_surfaces"])
        self.assertIn("stack-overwrite-candidate", r["dimensions"]["vulnerability_surfaces"])
        self.assertIn("pwn-format", r["leads"])
        self.assertTrue(any("checker semantics" in item for item in r["unresolved"]))
        self.assertTrue(any("format argument" in item for item in r["unresolved"]))
        validate(r, "rat.route-result/v1")

    def test_pwn_primary_does_not_invent_rev_shape_from_unattributed_score(self):
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
        self.assertFalse(r.get("conflict", False))
        self.assertEqual(r["dimensions"]["vulnerability_surfaces"], ["heap-lifetime-candidate"])
        self.assertEqual(r["dimensions"]["program_shapes"], [])  # ungrounded interesting score has no function evidence
        self.assertFalse(r["leads"])
        validate(r, "rat.route-result/v1")


    def test_fact_packing_preserves_underlying_pwn_and_checker_dimensions(self):
        rv = revq(
            imports=["malloc", "free", "memcmp"],
            functions=[{"name": "check", "calls": ["memcmp"]}],
        )
        rv["evasion_signal_schema"] = EVASION_SIGNAL_SCHEMA
        rv["evasion_signals"] = [
            {"kind": "packer-section", "value": {"section": "UPX0"}, "quality": "fact"},
        ]
        r = route(
            profile=profile(imports=["malloc", "free"]), revq=rv,
            interesting=[{"func": "check", "score": 8, "why": ["display-only"]}],
        )

        # A packing observation stays provisional while the underlying
        # shape and vulnerability surfaces remain explicit, unresolved leads.
        self.assertEqual(r["subroute"], "rev-packed")
        self.assertEqual(r["commitment"], "provisional")
        self.assertIsNone(r["skill"])
        self.assertIn("packing", r["dimensions"]["obstacles"])
        self.assertIn("heap-lifetime-candidate", r["dimensions"]["vulnerability_surfaces"])
        self.assertIn("checker", r["dimensions"]["program_shapes"])
        self.assertEqual(set(r["leads"]), {"pwn-heap", "rev-checker"})
        self.assertTrue(any("allocator imports" in x for x in r["unresolved"]))
        self.assertTrue(any("checker semantics" in x for x in r["unresolved"]))
        validate(r, "rat.route-result/v1")

    def test_kernel_priority_does_not_commit_with_competing_pwn_and_rev_leads(self):
        r = route(
            profile=profile(imports=["copy_from_user", "kmalloc", "malloc", "free"]),
            revq=revq(
                imports=["memcmp"], functions=[{"name": "check", "calls": ["memcmp"]}],
            ),
            interesting=[{"func": "check", "score": 8, "why": ["display-only"]}],
        )

        self.assertEqual(r["subroute"], "pwn-kernel")
        self.assertFalse(r.get("conflict", False))
        self.assertEqual(r["commitment"], "provisional")
        self.assertIsNone(r["skill"])
        self.assertEqual(set(r["leads"]), {"pwn-heap", "rev-checker"})
        self.assertIn("kernel-candidate", r["dimensions"]["program_shapes"])
        self.assertIn("checker", r["dimensions"]["program_shapes"])
        self.assertIn("heap-lifetime-candidate", r["dimensions"]["vulnerability_surfaces"])
        validate(r, "rat.route-result/v1")

    def test_packed_vm_hint_remains_visible_without_an_interesting_function(self):
        rv = revq(functions=[{"name": "vm_dispatch", "calls": []}])
        rv["evasion_signal_schema"] = EVASION_SIGNAL_SCHEMA
        rv["evasion_signals"] = [
            {"kind": "packer-section", "value": {"section": "UPX1"}, "quality": "fact"},
        ]
        r = route(revq=rv)
        self.assertEqual(r["subroute"], "rev-packed")
        self.assertIn("vm-candidate", r["dimensions"]["program_shapes"])
        self.assertIn("packing", r["dimensions"]["obstacles"])
        validate(r, "rat.route-result/v1")


    def test_low_ranked_structural_checker_is_not_hidden_by_high_interest_score(self):
        rv = revq(functions=[
            {"name": "noisy", "calls": []},
            {"name": "checker", "calls": ["memcmp"]},
        ])
        r = route(revq=rv, interesting=[
            {"func": "noisy", "score": 100, "why": ["display"]},
            {"func": "checker", "score": 1, "why": ["display"]},
        ])
        self.assertEqual(r["subroute"], "rev-checker")
        self.assertEqual(r["next"][0], {"query": "rat query func", "target": "checker"})
        self.assertEqual(r["commitment"], "provisional")
        self.assertIsNone(r["skill"])
        validate(r, "rat.route-result/v1")

    def test_unrelated_interest_score_cannot_change_pwn_route_or_next_probe(self):
        rv = revq(functions=[{"name": "noise", "calls": []}])
        outputs = [
            route(profile=profile(imports=["malloc", "free"]),
                  revq=rv, interesting=[{"func": "noise", "score": n, "why": []}])
            for n in (1, 1000)
        ]
        for result in outputs:
            self.assertEqual(result["subroute"], "pwn-heap")
            self.assertEqual(result["commitment"], "provisional")
            self.assertIsNone(result["skill"])
            self.assertIn("rev-symbolic", result["leads"])
        self.assertEqual(outputs[0]["next"], outputs[1]["next"])
        self.assertEqual(outputs[0]["dimensions"], outputs[1]["dimensions"])
        self.assertEqual(outputs[0]["leads"], outputs[1]["leads"])

    def test_packed_kernel_and_heap_are_unranked_coexisting_leads(self):
        rv = revq(functions=[{"name": "check", "calls": ["memcmp"]}])
        rv["evasion_signal_schema"] = EVASION_SIGNAL_SCHEMA
        rv["evasion_signals"] = [
            {"kind": "packer-section", "value": {"section": "UPX0"}, "quality": "fact"},
        ]
        r = route(profile=profile(imports=["copy_from_user", "malloc", "free"]),
                  revq=rv, interesting=[{"func": "check", "score": 5, "why": []}])
        self.assertEqual(r["subroute"], "rev-packed")  # compatibility label
        self.assertEqual(set(r["leads"]), {"pwn-kernel", "pwn-heap", "rev-checker"})
        self.assertFalse(r.get("conflict", False))
        self.assertNotIn("alternatives", r)
        self.assertTrue(all(isinstance(lead, str) for lead in r["leads"]))
        self.assertIsNone(r["skill"])
        self.assertEqual(
            sum(next_probe["query"] == "rat query pwn" for next_probe in r["next"]), 1
        )
        validate(r, "rat.route-result/v1")


if __name__ == "__main__":
    unittest.main()
