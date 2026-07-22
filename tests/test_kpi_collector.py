import pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"bin"))
from ratlib.benchmark import collect
def result(outcome="verified", challenge="x"):
 status="infra-failure" if outcome=="unknown" else "completed"
 return {"schema":"rat.benchmark-result/v1","benchmark_run_id":"r","ablation_id":"A3","corpus_digest":"sha256:x","challenge_id":challenge,"attempt":1,"status":status,"eligible":True,"outcome":outcome,"started_at":"2026-01-01T00:00:00Z","finished_at":"2026-01-01T00:00:01Z","category":"rev-native","difficulty":"easy","metrics":{"tts_seconds":1,"first_primitive_seconds":.5,"tokens":100,"strong_model_tokens":40,"duplicate_calls":0,"cacheable_invocations":1,"cache_hits":1,"cache_lookups":1,"top3_hit":True,"exploit_reliability_local":1,"exploit_reliability_remote":1,"context_compression_ratio":12},"oracle":{"passed":outcome=="verified","provenance_valid":True},"ground_truth":{"required_claims":["fact"],"active_claims":["fact"]}}
class KPI(unittest.TestCase):
 def test_metrics_do_not_turn_unknown_into_zero(self):
  d=collect([result(),result("unknown","y")]); self.assertEqual(d["metrics"]["verified_solve_at_1"],.5); self.assertEqual(d["metrics"]["false_solve_rate"],0)
if __name__=="__main__": unittest.main()
