import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.route import route
from ratlib.schema import validate

def profile(imports=(), facts=()):
    return {"imports": list(imports), "facts": [{"kind": k, "value": v} for k, v in facts]}

def revq(imports=(), evasion=(), functions=(), strings=()):
    return {"imports": list(imports), "evasion": list(evasion), "functions": list(functions),
            "strings": [{"val": s} for s in strings]}

class RouteFixtures(unittest.TestCase):
    def test_memcmp_checker_routes_rev_checker(self):
        r = route(revq=revq(imports=["memcmp"]),
                  interesting=[{"func": "check", "score": 8, "why": ["비교함수 호출: memcmp"]}])
        self.assertEqual(r["subroute"], "rev-checker")
        self.assertEqual(r["track"], "rev")
        self.assertGreater(r["confidence"], 0.5)

    def test_gets_without_nx_routes_pwn_stack(self):
        r = route(profile=profile(imports=["gets"], facts=[("elf.nx", False)]))
        self.assertEqual(r["subroute"], "pwn-stack")

    def test_gets_with_nx_routes_pwn_rop(self):
        r = route(profile=profile(imports=["gets"], facts=[("elf.nx", True)]))
        self.assertEqual(r["subroute"], "pwn-rop")

    def test_heap_imports_route_pwn_heap(self):
        r = route(profile=profile(imports=["malloc", "free"]))
        self.assertEqual(r["subroute"], "pwn-heap")

    def test_printf_plus_read_routes_pwn_format(self):
        r = route(profile=profile(imports=["printf", "read"]))
        self.assertEqual(r["subroute"], "pwn-format")

    def test_kernel_imports_route_pwn_kernel(self):
        r = route(profile=profile(imports=["copy_from_user", "kmalloc"]))
        self.assertEqual(r["subroute"], "pwn-kernel")

    def test_packed_evasion_routes_rev_packed(self):
        r = route(revq=revq(evasion=["패커 섹션 UPX0"]))
        self.assertEqual(r["subroute"], "rev-packed")
        self.assertEqual(r["track"], "rev")

    def test_vm_dispatch_hint_routes_rev_vm(self):
        r = route(revq=revq(functions=[{"name": "vm_dispatch_loop"}]))
        self.assertEqual(r["subroute"], "rev-vm")

    def test_no_signal_routes_unknown(self):
        r = route(profile=profile(), revq=revq())
        self.assertEqual(r["subroute"], "unknown")
        self.assertEqual(r["confidence"], 0.0)
        self.assertIsNone(r["skill"])

class RouteMixedSignal(unittest.TestCase):
    def test_heap_plus_generic_interesting_routes_pwn_heap_not_rev(self):
        r = route(profile=profile(imports=["malloc", "free"]),
                  revq=revq(imports=["malloc", "free", "memcmp"]),
                  interesting=[{"func": "wrong", "score": 3, "why": ["문자열 상수 비교 대상"]}])
        self.assertEqual(r["subroute"], "pwn-heap")
        self.assertTrue(r["conflict"])
        self.assertEqual(r["alternatives"][0]["subroute"], "rev-symbolic")

    def test_gets_plus_generic_interesting_routes_pwn_stack_not_rev(self):
        r = route(profile=profile(imports=["gets"], facts=[("elf.nx", False)]),
                  revq=revq(imports=["gets", "memcmp"]),
                  interesting=[{"func": "success", "score": 2, "why": ["문자열 상수 비교 대상"]}])
        self.assertEqual(r["subroute"], "pwn-stack")
        self.assertTrue(r["conflict"])

    def test_printf_read_plus_explicit_compare_call_still_routes_rev_checker(self):
        r = route(profile=profile(imports=["printf", "read"]),
                  revq=revq(imports=["printf", "read", "memcmp"]),
                  interesting=[{"func": "check_flag", "score": 8, "why": ["비교함수 호출: memcmp"]}])
        self.assertEqual(r["subroute"], "rev-checker")
        self.assertTrue(r["conflict"])
        self.assertEqual(r["alternatives"][0]["subroute"], "pwn-format")

class RouteDeterminism(unittest.TestCase):
    def test_identical_inputs_produce_identical_route(self):
        p, rv, inter = profile(imports=["gets"], facts=[("elf.nx", True)]), None, None
        self.assertEqual(route(profile=p, revq=rv, interesting=inter),
                          route(profile=p, revq=rv, interesting=inter))

class RouteDegradation(unittest.TestCase):
    def test_missing_revq_still_routes_from_profile_alone(self):
        r = route(profile=profile(imports=["gets"], facts=[("elf.nx", False)]), revq=None)
        self.assertEqual(r["capabilities"], {"profile": True, "revq": False})
        self.assertEqual(r["subroute"], "pwn-stack")

    def test_missing_profile_still_routes_from_revq_alone(self):
        r = route(profile=None, revq=revq(imports=["memcmp"]),
                  interesting=[{"func": "check", "score": 5, "why": ["비교함수 호출: memcmp"]}])
        self.assertEqual(r["capabilities"], {"profile": False, "revq": True})
        self.assertEqual(r["subroute"], "rev-checker")

    def test_no_artifacts_at_all_degrades_to_unknown_without_crashing(self):
        r = route()
        self.assertEqual(r["subroute"], "unknown")
        self.assertEqual(r["capabilities"], {"profile": False, "revq": False})

class RouteResultShape(unittest.TestCase):
    """signals/next must be structured, not plain strings."""
    def test_signals_are_structured_kind_value_quality(self):
        r = route(profile=profile(imports=["gets"], facts=[("elf.nx", False)]))
        self.assertTrue(r["signals"])
        for s in r["signals"]:
            self.assertEqual(set(s), {"kind", "value", "quality"})
            self.assertIn(s["quality"], {"fact", "heuristic"})

    def test_next_is_a_list_of_query_target_pairs(self):
        r = route(profile=profile(imports=["gets"], facts=[("elf.nx", False)]))
        self.assertIsInstance(r["next"], list)
        for n in r["next"]:
            self.assertEqual(set(n), {"query", "target"})

    def test_revq_interesting_signal_carries_func_and_score_as_heuristic(self):
        r = route(revq=revq(imports=["memcmp"]),
                   interesting=[{"func": "check", "score": 8, "why": ["비교함수 호출: memcmp"]}])
        interesting_signals = [s for s in r["signals"] if s["kind"] == "revq-interesting"]
        self.assertEqual(len(interesting_signals), 1)
        self.assertEqual(interesting_signals[0]["quality"], "heuristic")
        self.assertEqual(interesting_signals[0]["value"]["func"], "check")
        self.assertEqual(r["next"][0]["target"], "check")

    def test_import_based_signals_are_facts(self):
        r = route(profile=profile(imports=["malloc", "free"]))
        self.assertTrue(all(s["quality"] == "fact" for s in r["signals"]))

    def test_route_result_validates_against_schema(self):
        for r in (
            route(profile=profile(imports=["gets"], facts=[("elf.nx", True)])),
            route(revq=revq(evasion=["패커 섹션 UPX0"])),
            route(),
        ):
            validate(r, "rat.route-result/v1")

if __name__ == "__main__":
    unittest.main()
