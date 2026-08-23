import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.compact import truncate_by_item, truncate_lists_sharing_budget

class TruncateBySharedBudget(unittest.TestCase):
    """Regression: `rat query func` was giving each of callers/callees/strings
    its own full budget_bytes independently, so an envelope with N lists could
    grow to N*budget_bytes instead of being bounded by one query-level pool."""

    def test_single_list_matches_truncate_by_item(self):
        kept, trunc, omit = truncate_lists_sharing_budget([("a", [1, 2, 3])], 2)
        ref_kept, ref_trunc, ref_omit = truncate_by_item([1, 2, 3], 2)
        self.assertEqual(kept["a"], ref_kept)
        self.assertEqual(trunc, ref_trunc)
        self.assertEqual(omit["a"], ref_omit)

    def test_budget_is_shared_not_duplicated_per_list(self):
        # Each item costs 1 byte; independently applying budget=2 to each list
        # would keep 2 items from EVERY list (the bug). Shared budget must
        # exhaust after the first list.
        kept, truncated, omitted = truncate_lists_sharing_budget(
            [("callers", [1, 2, 3]), ("callees", [4, 5, 6]), ("strings", [7, 8, 9])], 2)
        total_kept = sum(len(v) for v in kept.values())
        self.assertLessEqual(total_kept, 2, "shared pool must not let 3 lists each keep up to budget")
        self.assertTrue(truncated)
        self.assertEqual(kept["callers"], [1, 2])
        self.assertEqual(kept["callees"], [])
        self.assertEqual(kept["strings"], [])
        self.assertEqual(omitted["callees"], 3)
        self.assertEqual(omitted["strings"], 3)

    def test_earlier_lists_get_priority_over_later_ones(self):
        kept, _, _ = truncate_lists_sharing_budget([("first", [1, 1, 1, 1]), ("second", [1, 1])], 3)
        self.assertEqual(len(kept["first"]), 3)
        self.assertEqual(len(kept["second"]), 0)

    def test_no_truncation_when_everything_fits_in_shared_budget(self):
        kept, truncated, omitted = truncate_lists_sharing_budget(
            [("a", [1]), ("b", [1])], 100)
        self.assertFalse(truncated)
        self.assertEqual(kept, {"a": [1], "b": [1]})
        self.assertEqual(omitted, {"a": 0, "b": 0})

    def test_empty_lists_are_handled(self):
        kept, truncated, omitted = truncate_lists_sharing_budget([("a", []), ("b", [])], 10)
        self.assertFalse(truncated)
        self.assertEqual(kept, {"a": [], "b": []})

if __name__ == "__main__":
    unittest.main()
