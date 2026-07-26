import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

from ratlib.benchmark import production_readiness, validate_corpus


class RealV1Pilot(unittest.TestCase):
    def test_release_eligible_pilot_inventory(self):
        root = ROOT / "benchmarks" / "corpus" / "real-v1"
        result = validate_corpus(root, strict=False)
        self.assertEqual(result["challenges"], 14)
        self.assertEqual(
            result["categories"],
            {"pwn-stack-format": 7, "rev-native": 4, "rev-vm-obfuscation": 3},
        )
        self.assertTrue(production_readiness(root)["release_eligible"])


if __name__ == "__main__":
    unittest.main()
