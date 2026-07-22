import pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"bin"))
from ratlib.benchmark import BenchmarkError, production_readiness, validate_corpus
class BenchmarkManifest(unittest.TestCase):
 def test_v1_distribution_and_oracles(self):
  r=validate_corpus(ROOT/"benchmarks/corpus/v1")
  self.assertEqual(r["challenges"],40); self.assertEqual(r["splits"],{"calibration":24,"holdout":16})
 def test_network_oracle_is_rejected(self):
  with self.assertRaises(BenchmarkError):
   from ratlib.benchmark import validate_challenge
   validate_challenge({"schema":"rat.benchmark-challenge/v1"})
 def test_v1_fixtures_are_not_release_eligible(self):
  readiness=production_readiness(ROOT/"benchmarks/corpus/v1")
  self.assertFalse(readiness["release_eligible"])
  self.assertTrue(any("known solve input" in x for x in readiness["defects"]))
if __name__=="__main__": unittest.main()
