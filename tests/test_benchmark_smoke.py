import json, pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class BenchmarkSmoke(unittest.TestCase):
 def test_local_fixture_oracle_pairs(self):
  p=subprocess.run([str(ROOT/"bin/rat-bench"),"run","--ablation","A3","--seed","1","--cache","cold","--subset","smoke","--fixture-smoke"],cwd=ROOT,text=True,capture_output=True)
  self.assertEqual(p.returncode,0,p.stderr)
  run=pathlib.Path(json.loads(p.stdout)["run_dir"])
  rows=[json.loads(x) for x in (run/"challenge-results.jsonl").read_text().splitlines()]
  self.assertEqual(len(rows),7); self.assertTrue(all(x["outcome"]=="verified" and x["oracle"]["passed"] for x in rows))
 def test_synthetic_corpus_cannot_produce_architecture_measurements(self):
  with tempfile.TemporaryDirectory() as d:
   runner=pathlib.Path(d)/"runner.py"
   runner.write_text("import json,sys; c=sys.argv[1]; print(json.dumps({'stdout':'verified:'+c+'\\n','solve_claimed':True,'active_claims':['fact','finding','primitive-or-solution'],'metrics':{'tts_seconds':1,'tokens':4}}))")
   command=f"python3 {runner} {{challenge}}"
   p=subprocess.run([str(ROOT/"bin/rat-bench"),"run","--ablation","A3","--seed","1","--cache","cold","--subset","smoke","--runner",command],cwd=ROOT,text=True,capture_output=True)
   self.assertEqual(p.returncode,5,p.stderr)
   self.assertIn("corpus is not eligible for architecture measurement",p.stderr)
if __name__=="__main__": unittest.main()
