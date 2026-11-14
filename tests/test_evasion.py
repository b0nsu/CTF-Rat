import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.evasion import SIGNAL_SCHEMA, classify, entropy, entropy_stream, has_current_contract, render_legacy


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

    def test_entropy_stream_matches_full_buffer_on_chunk_boundaries(self):
        payloads = [
            b"",
            b"\x00" * 17,
            bytes(range(256)),
            bytes(range(256)) * 17 + b"trailing",
            (bytes(range(256)) * 4097) + b"\xff",
        ]
        for data in payloads:
            with self.subTest(size=len(data)):
                self.assertEqual(entropy_stream(io.BytesIO(data), chunk_size=113), entropy(data))

    def test_entropy_stream_never_issues_unbounded_read(self):
        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                if size < 1 or size > 64:
                    raise AssertionError("unbounded stream read: %s" % size)
                return super().read(size)

        data = bytes(range(256)) * 41
        self.assertEqual(entropy_stream(BoundedReader(data), chunk_size=64), entropy(data))

    def test_entropy_stream_rejects_invalid_chunk_size(self):
        for size in (0, -1, True, 1.5, "64"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                entropy_stream(io.BytesIO(b"data"), chunk_size=size)


if __name__ == "__main__":
    unittest.main()
