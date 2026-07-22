import json, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class AblationMatrix(unittest.TestCase):
 def test_matrix(self):
  docs={p.stem:json.loads(p.read_text()) for p in (ROOT/"benchmarks/ablations").glob("*.yaml")}
  self.assertEqual(set(docs),{"A0","A1","A2","A3","A4","A5"})
  self.assertIn("skeptic",docs["A3"]["components"]); self.assertNotIn("context-governor",docs["A4"]["components"]); self.assertNotIn("skeptic",docs["A5"]["components"])
if __name__=="__main__": unittest.main()
