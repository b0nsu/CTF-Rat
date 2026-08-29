"""Guard: schemas/*.json reference docs cannot drift from ratlib/schema.py.

ratlib/schema.py's imperative validators are the single source of truth for the
runtime contract (they encode cross-field rules JSON Schema can't). The JSON
files are hand-authored reference docs surfaced by `state schema`. This suite
extracts each validator's field-level contract (via schema_docs, AST-based) and
asserts every dispatched schema has a JSON doc whose `required`/`properties`
agree with it -- so a future validator edit that forgets the doc fails CI.
"""
import json, os, pathlib, sys, unittest
import importlib.machinery
import importlib.util
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib import schema_docs as sd
from ratlib.schema import validate

SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), "..", "schemas")


class SchemaDocsInSync(unittest.TestCase):
    def _load(self, schema_id):
        path = os.path.join(SCHEMAS_DIR, sd.json_filename(schema_id))
        self.assertTrue(os.path.exists(path),
                        "missing reference doc schemas/%s for validated schema %s"
                        % (sd.json_filename(schema_id), schema_id))
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

    def _load_rat_module(self):
        path = os.path.join(os.path.dirname(__file__), "..", "bin", "rat")
        loader = importlib.machinery.SourceFileLoader("rat_cli_for_schema_docs_test", path)
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def _assert_schema_subset_accepts(self, schema, doc, path="$"):
        if "const" in schema:
            self.assertEqual(doc, schema["const"], "%s const mismatch" % path)
        if "enum" in schema:
            self.assertIn(doc, schema["enum"], "%s enum mismatch" % path)
        typ = schema.get("type")
        if isinstance(typ, list):
            if doc is None:
                self.assertIn("null", typ, "%s type mismatch" % path)
                return
            self.assertTrue(any(self._type_matches(doc, item) for item in typ if item != "null"),
                            "%s type mismatch" % path)
        elif typ is not None:
            self.assertTrue(self._type_matches(doc, typ), "%s type mismatch" % path)
        if isinstance(doc, dict):
            required = schema.get("required", [])
            self.assertTrue(set(required) <= set(doc), "%s required fields missing" % path)
            if schema.get("additionalProperties") is False:
                self.assertTrue(set(doc) <= set(schema.get("properties", {})), "%s has extra fields" % path)
            for key, subschema in schema.get("properties", {}).items():
                if key in doc:
                    self._assert_schema_subset_accepts(subschema, doc[key], "%s.%s" % (path, key))
        elif isinstance(doc, list) and "items" in schema:
            for index, item in enumerate(doc):
                self._assert_schema_subset_accepts(schema["items"], item, "%s[%d]" % (path, index))

    def _type_matches(self, value, typ):
        if typ == "object": return isinstance(value, dict)
        if typ == "array": return isinstance(value, list)
        if typ == "string": return isinstance(value, str)
        if typ == "integer": return isinstance(value, int) and not isinstance(value, bool)
        if typ == "number": return isinstance(value, (int, float)) and not isinstance(value, bool)
        if typ == "boolean": return isinstance(value, bool)
        if typ == "null": return value is None
        return True

    def test_every_dispatched_schema_has_a_matching_reference_doc(self):
        for schema_id in sd.dispatched_schemas():
            with self.subTest(schema=schema_id):
                doc = self._load(schema_id)
                required, allowed = sd.contract(schema_id)
                self.assertEqual(doc.get("$id"), schema_id, "wrong $id")
                # the field-level contract that drifted before: required must match exactly
                self.assertEqual(set(doc.get("required", [])), required,
                                 "required set diverges from validator")
                props = set(doc.get("properties", {}))
                # every required field must be documented
                self.assertTrue(required <= props, "required fields missing from properties")
                if allowed is not None:
                    # closed field set: the doc must enumerate exactly the allowed keys
                    self.assertEqual(props, allowed, "closed field set diverges from validator")
                    self.assertFalse(doc.get("additionalProperties", True),
                                     "closed-set schema must set additionalProperties:false")
                else:
                    # open set: properties may add documented optionals but not stray beyond
                    # nothing extra to assert on the closed side
                    pass

    def test_schema_const_pins_the_id(self):
        for schema_id in sd.dispatched_schemas():
            with self.subTest(schema=schema_id):
                doc = self._load(schema_id)
                const = doc.get("properties", {}).get("schema", {}).get("const")
                self.assertEqual(const, schema_id, "schema.const must pin the id")

    def test_query_result_reference_types_accept_producer_output(self):
        rat = self._load_rat_module()
        produced = rat._query_envelope(
            "func:main", status="ok",
            facts={"callers": [], "callees": [], "success_candidate_count": 0},
            heuristics={"next": [], "resolved": False},
            artifacts=[],
            coverage={"complete": True, "scope": "func:main", "omitted": []},
            diagnostics=[],
            provenance={"cache": {"hit": False}},
        )
        validate(produced, "rat.query-result/v1")
        self._assert_schema_subset_accepts(self._load("rat.query-result/v1"), produced)


if __name__ == "__main__":
    unittest.main()
