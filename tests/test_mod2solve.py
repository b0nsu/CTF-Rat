import itertools
import json
import pathlib
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.mod2linear import solve


class Mod2SolveTests(unittest.TestCase):
    def test_all_two_by_two_systems_modulo_four_against_brute_force(self):
        vectors = list(itertools.product(range(4), repeat=2))
        for entries in itertools.product(range(4), repeat=4):
            matrix = [list(entries[:2]), list(entries[2:])]
            possible = {}
            for x in vectors:
                rhs = tuple(sum(v * y for v, y in zip(row, x)) % 4 for row in matrix)
                possible.setdefault(rhs, []).append(list(x))
            for rhs in vectors:
                with self.subTest(matrix=matrix, rhs=rhs):
                    result = solve(matrix, list(rhs), 2)
                    answers = possible.get(rhs, [])
                    if not answers:
                        self.assertEqual(result["status"], "inconsistent")
                        self.assertIsNone(result["solution"])
                    else:
                        self.assertIn(result["solution"], answers)
                        self.assertEqual(result["unique"], len(answers) == 1)
                        self.assertTrue(result["checks"]["ax_matches_target"])

    def test_rectangular_even_negative_and_zero_systems(self):
        cases = [([[2, 4]], [6], 3), ([[2], [4]], [2, 4], 3),
                 ([[-2, 1], [0, 2]], [-1, 2], 8), ([[0, 0]], [0], 8),
                 ([[0, 0]], [1], 8), ([[2], [4]], [2, 0], 3)]
        for matrix, target, bits in cases:
            result = solve(matrix, target, bits)
            if result["solution"] is not None:
                self.assertTrue(result["checks"]["ax_matches_target"])
        self.assertEqual(solve([[2], [4]], [2, 0], 3)["status"], "inconsistent")

    def test_67_by_67_mod_256_recovers_known_input(self):
        rng = random.Random(84)
        size = 67
        matrix = [[rng.randrange(128) * 2 + (i == j) for j in range(size)] for i in range(size)]
        expected = [rng.randrange(256) for _ in range(size)]
        target = [sum(v * x for v, x in zip(row, expected)) % 256 for row in matrix]
        result = solve(matrix, target, 8)
        self.assertEqual(result["solution"], expected)
        self.assertTrue(result["unique"])

    def test_bounds_and_malformed_input(self):
        for matrix, target, bits in [([], [], 8), ([[1], [1, 2]], [0, 0], 8),
                                    ([[True]], [0], 8), ([[1]], [False], 8),
                                    ([[1]], [], 8), ([[1]], [0], True),
                                    ([[1]], [0], 65), ([[1] * 257], [0], 8),
                                    ([[1 << 129]], [0], 8)]:
            with self.subTest(matrix=matrix, bits=bits), self.assertRaises(ValueError):
                solve(matrix, target, bits)

    def test_cli_reports_hash_verification_and_distinct_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "system.json"
            for doc, code, status in [({"bits": 8, "matrix": [[3]], "target": [15]}, 0, "unique"),
                                      ({"bits": 8, "matrix": [[2]], "target": [1]}, 1, "inconsistent"),
                                      ({"bits": 8, "matrix": [[1]], "target": []}, 2, "error")]:
                source.write_text(json.dumps(doc))
                proc = subprocess.run([sys.executable, str(ROOT / "bin/mod2solve"), str(source)],
                                      capture_output=True, text=True, timeout=10)
                self.assertEqual(proc.returncode, code, proc.stderr)
                result = json.loads(proc.stdout)
                self.assertEqual(result["status"], status)
                if code == 0:
                    self.assertEqual(result["solution_hex"], "05")
                    self.assertTrue(result["artifact"]["sha256"].startswith("sha256:"))
                    self.assertTrue(result["checks"]["ax_matches_target"])


if __name__ == "__main__":
    unittest.main()
