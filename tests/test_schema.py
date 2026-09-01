import json, os, pathlib, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.schema import validate, ValidationError

def route_result(**overrides):
    doc = {"schema": "rat.route-result/v1", "track": "pwn", "subroute": "pwn-stack", "confidence": 0.6,
           "signals": [{"kind": "overflow-imports", "value": ["gets"], "quality": "fact"}],
           "capabilities": {"profile": True, "revq": False}, "skill": "pwn-stack",
           "next": [{"query": "pwncalc", "target": None}]}
    doc.update(overrides)
    return doc

def active_route(**overrides):
    doc = route_result(
        skill=None,
        commitment="provisional",
        dimensions={"vulnerability_surfaces": ["stack-overwrite-candidate"],
                    "program_shapes": [], "obstacles": [], "constraints": []},
        unresolved=["prove overwrite"],
        score_semantics="heuristic-rank-not-probability",
    )
    doc.update(overrides)
    return doc

def query_result(**overrides):
    doc = {"schema": "rat.query-result/v1", "query": "func:main", "status": "ok", "facts": {},
           "heuristics": {}, "artifacts": [], "coverage": {"complete": True, "scope": "x", "omitted": None},
           "diagnostics": [], "provenance": {"cache": {"hit": False}}}
    doc.update(overrides)
    return doc

def cache_stats(**overrides):
    doc = {"schema": "rat.cache-stats/v1", "store": "/tmp/x", "total_entries": 0, "by_backend": {},
           "oldest_produced_at": None, "newest_produced_at": None}
    doc.update(overrides)
    return doc

class RouteResultSchema(unittest.TestCase):
    def test_valid_doc_passes(self):
        validate(route_result())

    def test_legacy_route_without_active_triage_overlay_still_passes(self):
        validate(route_result())

    def test_valid_optional_active_triage_overlay_passes(self):
        validate(active_route())

    def test_missing_field_raises(self):
        d = route_result(); del d["skill"]
        with self.assertRaises(ValidationError): validate(d)

    def test_confidence_out_of_range_raises(self):
        with self.assertRaises(ValidationError): validate(route_result(confidence=1.5))

    def test_signal_missing_quality_raises(self):
        with self.assertRaises(ValidationError):
            validate(route_result(signals=[{"kind": "x", "value": "y"}]))

    def test_signal_bad_quality_raises(self):
        with self.assertRaises(ValidationError):
            validate(route_result(signals=[{"kind": "x", "value": "y", "quality": "guess"}]))

    def test_next_missing_target_raises(self):
        with self.assertRaises(ValidationError):
            validate(route_result(next=[{"query": "x"}]))

    def test_alternatives_field_allowed_with_valid_shape(self):
        d = route_result(); d["conflict"] = True
        d["alternatives"] = [{"track": "pwn", "subroute": "pwn-stack", "confidence": 0.6}]
        validate(d)

    def test_alternatives_field_rejected_when_not_a_list(self):
        d = route_result(); d["alternatives"] = "rev-symbolic"
        with self.assertRaises(ValidationError): validate(d)

    def test_alternatives_element_missing_field_raises(self):
        d = route_result(); d["alternatives"] = [{"track": "pwn", "subroute": "pwn-stack"}]
        with self.assertRaises(ValidationError): validate(d)

    def test_alternatives_element_confidence_out_of_range_raises(self):
        d = route_result()
        d["alternatives"] = [{"track": "pwn", "subroute": "pwn-stack", "confidence": 1.5}]
        with self.assertRaises(ValidationError): validate(d)

    def test_conflict_must_be_bool(self):
        d = route_result(); d["conflict"] = "yes"
        with self.assertRaises(ValidationError): validate(d)

    def test_conflict_true_without_alternatives_raises(self):
        d = route_result(); d["conflict"] = True
        with self.assertRaises(ValidationError): validate(d)

    def test_conflict_true_with_empty_alternatives_raises(self):
        d = route_result(); d["conflict"] = True; d["alternatives"] = []
        with self.assertRaises(ValidationError): validate(d)

    def test_alternatives_without_conflict_raises(self):
        d = route_result()
        d["alternatives"] = [{"track": "pwn", "subroute": "pwn-stack", "confidence": 0.6}]
        with self.assertRaises(ValidationError): validate(d)

    def test_alternatives_with_conflict_false_raises(self):
        d = route_result(); d["conflict"] = False
        d["alternatives"] = [{"track": "pwn", "subroute": "pwn-stack", "confidence": 0.6}]
        with self.assertRaises(ValidationError): validate(d)

    def test_no_conflict_no_alternatives_passes(self):
        validate(route_result(conflict=False))

    def test_provisional_route_cannot_lock_skill(self):
        with self.assertRaises(ValidationError):
            validate(active_route(skill="pwn-stack"))

    def test_unknown_route_cannot_lock_skill(self):
        with self.assertRaises(ValidationError):
            validate(active_route(commitment="unknown", skill="rev-symbolic"))

    def test_conflicting_active_route_must_be_provisional(self):
        d = active_route(commitment="committed", skill="rev-checker", conflict=True,
                         alternatives=[{"track": "pwn", "subroute": "pwn-format", "confidence": 0.55}])
        with self.assertRaises(ValidationError): validate(d)

    def test_overlay_is_all_or_nothing_for_backward_compatibility(self):
        d = route_result(commitment="provisional", skill=None)
        with self.assertRaises(ValidationError): validate(d)

    def test_dimensions_require_all_four_orthogonal_axes(self):
        d = active_route(dimensions={"vulnerability_surfaces": [], "program_shapes": [], "obstacles": []})
        with self.assertRaises(ValidationError): validate(d)

    def test_bad_score_semantics_raises(self):
        with self.assertRaises(ValidationError):
            validate(active_route(score_semantics="probability"))

    def test_reference_schema_describes_active_triage_overlay(self):
        repo = pathlib.Path(__file__).resolve().parents[1]
        schema = json.loads((repo / "schemas" / "rat.route-result.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["commitment"]["enum"], ["committed", "provisional", "unknown"])
        self.assertEqual(schema["properties"]["score_semantics"]["const"], "heuristic-rank-not-probability")
        self.assertEqual(set(schema["properties"]["dimensions"]["required"]),
                         {"vulnerability_surfaces", "program_shapes", "obstacles", "constraints"})

class QueryResultSchema(unittest.TestCase):
    def test_valid_doc_passes_for_each_status(self):
        for status in ("ok", "partial", "error"):
            validate(query_result(status=status,
                                  coverage={"complete": status == "ok", "scope": "x", "omitted": None}))

    def test_invalid_status_raises(self):
        with self.assertRaises(ValidationError): validate(query_result(status="pending"))

    def test_missing_coverage_field_raises(self):
        with self.assertRaises(ValidationError):
            validate(query_result(coverage={"complete": True, "scope": "x"}))

    def test_unknown_diagnostic_code_raises(self):
        with self.assertRaises(ValidationError):
            validate(query_result(diagnostics=[{"code": "not-a-real-code", "message": "x"}]))

    def test_known_diagnostic_codes_pass(self):
        for code in ("input_invalid", "dependency_missing", "timeout", "partial", "stale_cache", "ambiguous", "verification_fail"):
            validate(query_result(diagnostics=[{"code": code, "message": "x"}]))

    def test_missing_provenance_cache_raises(self):
        with self.assertRaises(ValidationError):
            validate(query_result(provenance={}))

    def test_extra_fields_allowed_not_strict(self):
        d = query_result(); d["governor"] = {"stuck": True, "action": "re-route-or-deep-escalate", "reason": "x"}
        validate(d)

    def test_reference_schema_matches_runtime_object_shape(self):
        repo = pathlib.Path(__file__).resolve().parents[1]
        schema = json.loads((repo / "schemas" / "rat.query-result.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["facts"]["type"], "object")
        self.assertEqual(schema["properties"]["heuristics"]["type"], "object")
        self.assertEqual(schema["properties"]["coverage"]["properties"]["complete"]["type"], "boolean")
        self.assertTrue(schema["allOf"])
        validate(query_result(facts={"key": "value"}, heuristics={"next": []}), "rat.query-result/v1")
        with self.assertRaises(ValidationError):
            validate(query_result(facts=[], heuristics={}), "rat.query-result/v1")

class CacheStatsSchema(unittest.TestCase):
    def test_valid_doc_passes(self):
        validate(cache_stats())

    def test_negative_total_entries_raises(self):
        with self.assertRaises(ValidationError): validate(cache_stats(total_entries=-1))

    def test_unknown_field_raises_because_strict(self):
        d = cache_stats(); d["extra"] = 1
        with self.assertRaises(ValidationError): validate(d)

if __name__ == "__main__":
    unittest.main()
