import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.governor import check_progress, DEFAULT_WINDOW

class ProgressNoveltyGovernor(unittest.TestCase):
    def test_insufficient_history_is_never_stuck(self):
        out = check_progress([False, False])
        self.assertFalse(out["stuck"])
        self.assertIsNone(out["action"])

    def test_five_consecutive_non_novel_actions_are_stuck(self):
        out = check_progress([False] * DEFAULT_WINDOW)
        self.assertTrue(out["stuck"])
        self.assertEqual(out["action"], "re-route-or-deep-escalate")
        self.assertIn("5 actions", out["reason"])

    def test_one_novel_action_within_window_prevents_stuck(self):
        out = check_progress([False, False, True, False, False])
        self.assertFalse(out["stuck"])

    def test_only_the_trailing_window_is_considered(self):
        history = [True] + [False] * DEFAULT_WINDOW
        out = check_progress(history)
        self.assertTrue(out["stuck"])

    def test_custom_window_size(self):
        self.assertFalse(check_progress([False, False], window=3)["stuck"])
        self.assertTrue(check_progress([False, False, False], window=3)["stuck"])

if __name__ == "__main__":
    unittest.main()
