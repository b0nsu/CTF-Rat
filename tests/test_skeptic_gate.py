import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import GateError, enter, report_skeptic
class SkepticGateTests(unittest.TestCase):
 def test_report_without_completed_skeptic_task_is_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   enter(d,"solve-P0")
   with self.assertRaises(GateError): report_skeptic(d,{"schema":"rat.skeptic-report/v1","report_id":"r","run_id":"local","task_id":"x","exploit_task_id":"y","verdict":"accept","counterexamples":[],"affected_ids":[],"residual_risks":[]})
