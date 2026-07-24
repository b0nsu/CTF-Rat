import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__),"..","bin"))
from ratlib.orchestration import GateError, enter, finish_phase, plan_fanout
class FanoutTests(unittest.TestCase):
 def test_trigger_and_cap_are_fail_closed(self):
  with tempfile.TemporaryDirectory() as d:
   enter(d,"solve-P0"); finish_phase(d,"solve-P0"); enter(d,"solve-P1"); finish_phase(d,"solve-P1"); enter(d,"solve-P2")
   branches=[{"hypothesis_id":"h%d"%n,"objective":"o%d"%n,"falsification":"f%d"%n,"evidence_ids":["e%d"%n]} for n in range(4)]
   with self.assertRaises(GateError): plan_fanout(d,branches,{"uncertainty_set":["x"],"evidence_ids":["e"]},{"remaining":100,"per_branch":10,"converge":10})
   with self.assertRaises(GateError): plan_fanout(d,branches[:2],{}, {"remaining":100,"per_branch":10,"converge":10})
