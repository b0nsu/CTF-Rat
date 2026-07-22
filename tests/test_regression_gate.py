import pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"bin"))
from ratlib.benchmark import BenchmarkError, collect, compare, release_plan, threshold_gate, validate_lock, validate_transcript
class Regression(unittest.TestCase):
 def test_false_solve_is_hard_fail(self):
  m={"schema":"rat.benchmark-metrics/v1","metrics":{"false_solve_rate":.1},"categories":{}}
  t={"schema":"rat.benchmark-thresholds/v1","source":{"sha256":"x","document":"x"},"targets":{}}
  self.assertFalse(threshold_gate(m,t)["passed"])
 def test_relative_targets_and_unknowns_fail_closed(self):
  thresholds={"schema":"rat.benchmark-thresholds/v1","source":{"sha256":"x","document":"x"},"targets":{"verified_solve_at_1":{"relative_min":.15,"source":"x"},"cache_hit_rate":{"min":.6,"source":"x"}}}
  candidate={"schema":"rat.benchmark-metrics/v1","metrics":{"verified_solve_at_1":.9,"cache_hit_rate":None,"false_solve_rate":0}}
  reference={"schema":"rat.benchmark-metrics/v1","ablation_id":"A0","metrics":{"verified_solve_at_1":1.0}}
  gate=threshold_gate(candidate,thresholds,reference)
  self.assertFalse(gate["passed"]); self.assertIn("cache_hit_rate",gate["unknown"])
  self.assertTrue(any("relative change" in x for x in gate["failures"]))
 def test_relative_targets_reject_non_a0_reference(self):
  t={"schema":"rat.benchmark-thresholds/v1","source":{"sha256":"x","document":"x"},"targets":{"verified_solve_at_1":{"relative_min":.15,"source":"x"}}}
  c={"schema":"rat.benchmark-metrics/v1","metrics":{"verified_solve_at_1":.9,"false_solve_rate":0}}
  wrong={"schema":"rat.benchmark-metrics/v1","ablation_id":"A3","metrics":{"verified_solve_at_1":.7}}
  self.assertFalse(threshold_gate(c,t,wrong)["passed"])
 def test_collect_rejects_mixed_run_or_ablation(self):
  def row(run,ablation):
   return {"schema":"rat.benchmark-result/v1","benchmark_run_id":run,"ablation_id":ablation,"corpus_digest":"sha256:x","challenge_id":run+ablation,"attempt":1,"status":"completed","eligible":True,"outcome":"verified","started_at":"x","finished_at":"x","metrics":{},"oracle":{"passed":True},"ground_truth":{"required_claims":[],"active_claims":[]}}
  with self.assertRaises(BenchmarkError): collect([row("a","A0"),row("b","A0")])
  with self.assertRaises(BenchmarkError): collect([row("a","A0"),row("a","A1")])
 def test_solve_drop_is_regression(self):
  samples={str(i):{"verified":True,"metrics":{}} for i in range(20)}
  bad={str(i):{"verified":False,"metrics":{}} for i in range(20)}
  b={"schema":"rat.benchmark-metrics/v1","metrics":{"verified_solve_at_1":1.0},"categories":{},"samples":samples}; c={"schema":"rat.benchmark-metrics/v1","metrics":{"verified_solve_at_1":0.0},"categories":{},"samples":bad}
  self.assertIn("verified_solve_at_1",compare(c,b)["regressions"])
 def test_collect_rejects_duplicate_attempt(self):
  row={"schema":"rat.benchmark-result/v1","benchmark_run_id":"r","ablation_id":"A3","corpus_digest":"sha256:x","challenge_id":"x","attempt":1,"status":"completed","eligible":True,"outcome":"verified","started_at":"x","finished_at":"x","metrics":{},"oracle":{"passed":True},"ground_truth":{"required_claims":[],"active_claims":[]}}
  with self.assertRaises(BenchmarkError): collect([row,row.copy()])
 def test_unapproved_lock_cannot_run_nightly(self):
  lock={"schema":"rat.benchmark-baseline-lock/v1","baseline_id":"x","corpus_digest":"x","thresholds":"x","ctf_rat_commit":"x","schema_bundle":"x","toolchain":"x","model_agent":"x","resource_policy":"x","seed_set":[1],"status":"template-not-approved"}
  with self.assertRaises(BenchmarkError): validate_lock(lock)
 def test_transcript_needs_two_distinct_people(self):
  threshold={"baseline_id":"x","source":{"sha256":"sha256:x"}}
  pending={"schema":"rat.benchmark-transcript/v1","baseline_id":"x","source_sha256":"sha256:x","reviewers":[],"status":"pending-two-person-review"}
  with self.assertRaises(BenchmarkError): validate_transcript(pending,threshold)
  self.assertEqual(release_plan()["total_runs"],23)
if __name__=="__main__": unittest.main()
