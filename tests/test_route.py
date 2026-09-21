import copy, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.route import route
from ratlib.schema import ValidationError, validate

def rev_checker():
    return {"functions":[{"name":"check","calls":["memcmp@GLIBC_2.2.5"],"strings":["Correct","Wrong"]}]}

class RouterV2(unittest.TestCase):
    def test_contract_has_no_ranking_or_representative_fields(self):
        doc=route(profile={"imports":["gets"],"facts":[{"kind":"elf.nx","value":True}]})
        validate(doc,"rat.route-result/v2")
        self.assertFalse({"track","subroute","confidence","alternatives","score_semantics","conflict"}&set(doc))
        self.assertEqual(doc["commitment"],"provisional"); self.assertIsNone(doc["skill"])

    def test_dimensions_coexist_without_erasing_evidence(self):
        doc=route(profile={"imports":["malloc","free","printf","read","gets"]},
                  revq=rev_checker(),interesting=[{"func":"check","score":9}])
        self.assertEqual(set(doc["dimensions"]["vulnerability_surfaces"]),
                         {"heap-lifetime-candidate","format-string-candidate","stack-overwrite-candidate"})
        self.assertIn("checker",doc["dimensions"]["program_shapes"])
        self.assertEqual(doc["decision"]["action"],"rat query func")

    def test_observation_order_does_not_change_meaning(self):
        profile={"imports":["free","gets","malloc","printf","read"],"facts":[{"kind":"elf.nx","value":True}]}
        a=route(profile=profile,revq=rev_checker(),interesting=[{"func":"check","score":1}])
        profile["imports"].reverse(); b=route(profile=profile,revq=copy.deepcopy(rev_checker()),interesting=[{"func":"check","score":99}])
        self.assertEqual(a,b)

    def test_imports_never_commit_or_lock_skill(self):
        for imports in (["malloc","free"],["printf","read"],["gets"],["copy_from_user"]):
            doc=route(profile={"imports":imports})
            self.assertEqual(doc["commitment"],"provisional"); self.assertIsNone(doc["skill"])

    def test_no_evidence_is_unknown(self):
        doc=route(); self.assertEqual(doc["commitment"],"unknown"); self.assertIsNone(doc["decision"])

    def test_old_fields_are_rejected_with_regeneration_command(self):
        doc=route(); doc["confidence"]=.5
        with self.assertRaisesRegex(ValidationError,"rat route <bin>"): validate(doc)

    def test_typed_packing_and_checker_both_survive(self):
        rev=rev_checker(); rev.update({"evasion_signal_schema":"rat.evasion-signals/v1","evasion_signals":[{"kind":"packer-section","value":"UPX0","quality":"fact"}]})
        doc=route(profile={"imports":["malloc"]},revq=rev,interesting=[{"func":"check"}])
        self.assertIn("packing",doc["dimensions"]["obstacles"]); self.assertIn("checker",doc["dimensions"]["program_shapes"])

    def test_pe_preserves_independent_vulnerability_evidence_but_limits_actions(self):
        imports=["malloc","free","printf","read","gets"]
        elf=route(profile={"imports":imports},revq={"platform":"elf"})
        pe=route(profile={"imports":imports},revq={"platform":"pe"})
        expected={"heap-lifetime-candidate","format-string-candidate","stack-overwrite-candidate"}
        self.assertEqual(set(elf["dimensions"]["vulnerability_surfaces"]),expected)
        self.assertEqual(set(pe["dimensions"]["vulnerability_surfaces"]),expected)
        for kind in ("heap-imports","format-input-imports","overflow-imports"):
            self.assertTrue(any(signal["kind"] == kind for signal in pe["signals"]))
        self.assertFalse(any(action["query"] == "rat query pwn" for action in pe["next"]))
        self.assertTrue(any(action["query"].endswith("qiling_trace.py") for action in pe["next"]))

if __name__ == "__main__": unittest.main()
