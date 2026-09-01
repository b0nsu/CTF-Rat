import pathlib, sys, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from ratlib.cards import project_pwn_capability


def profile(imports=(), facts=()):
    return {
        "schema": "rat.binary-profile/v1",
        "inputs": [{"role": "binary", "digest": "sha256:" + "1" * 64}],
        "imports": list(imports),
        "facts": [{"kind": kind, "value": value} for kind, value in facts],
    }


class PwnCapabilityCard(unittest.TestCase):
    def test_strong_overflow_with_nx_routes_to_rop_without_claiming_a_primitive(self):
        card = project_pwn_capability(profile(
            imports=("gets",),
            facts=(("elf.nx", True), ("elf.pie", False), ("elf.canary", False)),
        ))
        self.assertEqual(card["kind"], "pwn-capability")
        self.assertEqual(card["facts"]["sinks"]["overflow_unbounded"], ["gets"])
        self.assertEqual(card["facts"]["protections"]["elf.nx"], True)
        self.assertEqual(card["heuristics"]["candidate_routes"][0]["subroute"], "pwn-rop")
        self.assertNotIn("verified_primitive", card["facts"])
        self.assertTrue(any("does not prove RIP/PC control" in x for x in card["heuristics"]["limitations"]))

    def test_format_and_overflow_candidates_preserve_primary_and_sibling(self):
        card = project_pwn_capability(profile(
            imports=("printf", "read"),
            facts=(("elf.nx", True),),
        ))
        routes = card["heuristics"]["candidate_routes"]
        self.assertEqual(routes[0]["subroute"], "pwn-format")
        self.assertTrue(routes[0]["primary"])
        self.assertIn("pwn-rop", {r["subroute"] for r in routes[1:]})
        self.assertEqual(card["facts"]["sinks"]["format"], ["printf"])
        self.assertEqual(card["facts"]["sinks"]["overflow_bounded"], ["read"])

    def test_versioned_elf_imports_are_canonicalized_before_projection_and_route(self):
        card = project_pwn_capability(profile(
            imports=("printf@GLIBC_2.2.5", "read@@GLIBC_2.2.5"),
            facts=(("elf.nx", True),),
        ))
        self.assertEqual(card["facts"]["sinks"]["format"], ["printf"])
        self.assertEqual(card["facts"]["sinks"]["overflow_bounded"], ["read"])
        self.assertEqual(card["facts"]["imports_total"], 2)
        routes = card["heuristics"]["candidate_routes"]
        self.assertEqual(routes[0]["subroute"], "pwn-format")
        self.assertIn("pwn-rop", {r["subroute"] for r in routes[1:]})

    def test_command_import_is_attention_fact_not_a_vulnerability_route(self):
        card = project_pwn_capability(profile(imports=("system",)))
        self.assertEqual(card["facts"]["sinks"]["command_exec"], ["system"])
        self.assertEqual(card["heuristics"]["candidate_routes"], [])

    def test_projection_is_deterministic_and_deduplicates_imports(self):
        p = profile(imports=("read", "read@GLIBC_2.2.5", "printf"), facts=(("elf.nx", True),))
        self.assertEqual(project_pwn_capability(p), project_pwn_capability(p))
        self.assertEqual(project_pwn_capability(p)["facts"]["imports_total"], 2)


if __name__ == "__main__":
    unittest.main()
