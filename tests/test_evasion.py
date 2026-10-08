import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.evasion import SIGNAL_SCHEMA, classify, entropy, has_current_contract, render_legacy


class EvasionSignalTests(unittest.TestCase):
    def test_typed_signals_preserve_fact_vs_heuristic(self):
        signals = classify(
            ["ptrace", "memcmp"],
            ["please no TracerPid here"],
            7.6,
            ["UPX0", ".text"],
        )
        by_kind = {signal["kind"]: signal for signal in signals}
        self.assertEqual(by_kind["anti-debug-import"]["quality"], "fact")
        self.assertEqual(by_kind["anti-debug-import"]["value"], {"api": "ptrace"})
        self.assertEqual(by_kind["anti-debug-string"]["quality"], "heuristic")
        self.assertEqual(by_kind["high-entropy"]["quality"], "heuristic")
        self.assertEqual(by_kind["high-entropy"]["value"]["entropy"], 7.6)
        self.assertEqual(by_kind["packer-section"]["quality"], "fact")
        self.assertEqual(by_kind["packer-section"]["value"], {"section": "UPX0"})

    def test_legacy_renderer_is_one_way_compatibility_surface(self):
        signals = classify(["ptrace"], ["TracerPid"], 7.54, ["UPX1"])
        rendered = render_legacy(signals)
        self.assertIn("import ptrace", rendered)
        self.assertIn("문자열 'tracerpid'", rendered)
        self.assertIn("고엔트로피 7.54/8 (packing/암호화 의심)", rendered)
        self.assertIn("패커 섹션 UPX1", rendered)

    def test_normal_binary_has_no_evasion_signal(self):
        self.assertEqual(classify(["memcmp"], ["hello world"], 5.0, [".text", ".data"]), [])

    def test_contract_rejects_legacy_sidecar_without_typed_field(self):
        self.assertFalse(has_current_contract({"schema": 2, "evasion": ["패커 섹션 UPX0"]}))
        self.assertTrue(has_current_contract({
            "schema": 2,
            "evasion_signal_schema": SIGNAL_SCHEMA,
            "evasion_signals": [],
        }))

    def test_entropy_bounds(self):
        self.assertEqual(entropy(b"\x00" * 16), 0.0)
        self.assertGreater(entropy(bytes(range(256))), 7.9)


if __name__ == "__main__":
    unittest.main()
