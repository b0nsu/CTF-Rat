import json, pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"bin"))
from ratlib.route import route
from ratlib.schema import ValidationError, validate

class RouteResultSchema(unittest.TestCase):
    def test_v2_valid(self): validate(route(),"rat.route-result/v2")
    def test_v1_has_no_validator_or_reference_schema(self):
        with self.assertRaisesRegex(ValidationError,"regenerate with `rat route <bin>`"):
            validate({"schema":"rat.route-result/v1"})
        self.assertFalse((ROOT/"schemas/rat.route-result.v1.json").exists())
    def test_reference_schema_excludes_old_fields(self):
        schema=json.loads((ROOT/"schemas/rat.route-result.v2.json").read_text())
        self.assertFalse({"track","subroute","confidence","alternatives","score_semantics"}&set(schema["properties"]))
    def test_nested_error_envelope_has_no_v1_fields(self):
        doc=route(); doc["error"]={"code":"input_invalid","message":"regenerate with rat route <bin>"}; validate(doc)
        self.assertFalse({"track","subroute","confidence"}&set(doc))

class OtherSchemas(unittest.TestCase):
    def test_query(self):
        d={"schema":"rat.query-result/v1","query":"x","status":"ok","facts":{},"heuristics":{},"artifacts":[],"coverage":{"complete":True,"scope":"x","omitted":[]},"diagnostics":[],"provenance":{"cache":{}}}
        validate(d)
    def test_cache(self):
        d={"schema":"rat.cache-stats/v1","store":"x","total_entries":0,"by_backend":{},"oldest_produced_at":None,"newest_produced_at":None}
        validate(d)
if __name__=="__main__": unittest.main()
