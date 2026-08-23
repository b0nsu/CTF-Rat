import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.route import route

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

if __name__ == "__main__":
    unittest.main()
