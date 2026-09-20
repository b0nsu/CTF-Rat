"""Pure regression coverage for the bounded revq global-callgraph projection."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))

from ratlib.graph_projection import project_graph
from ratlib.schema import validate


def sample():
    return {
        "engine": "angr", "analysis_complete": True, "sha256": "f" * 64,
        "functions": [
            {"name": "transform", "addr": 0x1400, "size": 20, "nblocks": 2,
             "ncallers": 1, "calls": [], "strings": []},
            {"name": "check", "addr": 0x1300, "size": 35, "nblocks": 4,
             "ncallers": 1, "calls": ["transform", "memcmp"], "strings": []},
            {"name": "main", "addr": 0x1200, "size": 50, "nblocks": 3,
             "ncallers": 0, "calls": ["check", "read"], "strings": []},
        ],
    }


class ProjectionTests(unittest.TestCase):
    def test_full_projection_uses_addresses_and_does_not_invent_external_edges(self):
        out = project_graph(sample(), budget_bytes=8192, max_nodes=10)
        facts, coverage = out["facts"], out["coverage"]
        self.assertTrue(coverage["complete"])
        self.assertEqual(facts["recovered_functions"], 3)
        self.assertEqual(facts["visible_internal_edges"], 2)
        nodes = {n["name"]: n for n in facts["graph"]}
        self.assertEqual(nodes["main"]["calls"], ["0x1300"])
        self.assertEqual(nodes["main"]["named_targets"], ["read"])
        self.assertEqual(nodes["check"]["calls"], ["0x1400"])
        self.assertEqual(nodes["check"]["named_targets"], ["memcmp"])

    def test_budget_does_not_silently_relabel_hidden_edges_as_visible(self):
        out = project_graph(sample(), max_nodes=1)
        self.assertFalse(out["coverage"]["complete"])
        self.assertEqual(out["facts"]["visible_functions"], 1)
        self.assertEqual(out["facts"]["graph"][0]["name"], "main")
        self.assertEqual(out["facts"]["graph"][0]["calls"], [])
        self.assertEqual(out["facts"]["graph"][0]["hidden_calls"], 1)
        self.assertEqual(out["coverage"]["omitted"]["functions"], 2)

    def test_tiny_budget_returns_partial_without_splitting_a_node(self):
        out = project_graph(sample(), budget_bytes=1)
        self.assertEqual(out["facts"]["graph"], [])
        self.assertFalse(out["coverage"]["complete"])
        self.assertEqual(out["coverage"]["omitted"]["functions"], 3)

    def test_ambiguous_symbol_does_not_become_a_false_internal_edge(self):
        rev = sample()
        rev["functions"].append({"name": "check", "addr": 0x1600, "nblocks": 1,
                                 "size": 2, "ncallers": 0, "calls": []})
        out = project_graph(rev, max_nodes=10, budget_bytes=8192)
        self.assertFalse(out["coverage"]["complete"])
        main = next(n for n in out["facts"]["graph"] if n["name"] == "main")
        self.assertEqual(main["calls"], [])
        self.assertEqual(main["ambiguous_calls"], 1)

    def test_binutils_is_explicitly_partial_even_without_omissions(self):
        rev = sample()
        rev.update(engine="binutils", analysis_complete=False)
        out = project_graph(rev, max_nodes=10, budget_bytes=8192)
        self.assertFalse(out["coverage"]["complete"])
        self.assertTrue(out["diagnostics"])

    def test_order_and_output_are_stable(self):
        a = project_graph(sample(), interesting=[{"func": "check", "score": 10}])
        b = project_graph(sample(), interesting=[{"func": "check", "score": 10}])
        self.assertEqual(a, b)
        self.assertEqual([n["name"] for n in a["facts"]["graph"]],
                         ["main", "check", "transform"])

    def test_non_addressed_functions_are_reported(self):
        rev = sample()
        rev["functions"].append({"name": "unknown", "addr": 0, "calls": []})
        out = project_graph(rev)
        self.assertEqual(out["coverage"]["omitted"]["non_addressed_functions"], 1)

    def test_rejects_invalid_budget_and_max_nodes(self):
        for params in ({"budget_bytes": 0}, {"max_nodes": 0}):
            with self.assertRaises(ValueError):
                project_graph(sample(), **params)


class FrontDoorTests(unittest.TestCase):
    def test_graph_subcommand_missing_file_is_a_schema_valid_input_error(self):
        with tempfile.TemporaryDirectory() as work:
            missing = str(pathlib.Path(work) / "missing")
            p = subprocess.run([sys.executable, str(BIN / "rat"), "query", "graph", missing,
                                "--format", "json"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 4, p.stderr)
        doc = json.loads(p.stdout)
        validate(doc, "rat.query-result/v1")
        self.assertEqual(doc["status"], "error")
        self.assertEqual(doc["diagnostics"][0]["code"], "input_invalid")

    def test_graph_subcommand_uses_existing_revq_and_envelope(self):
        loader = importlib.machinery.SourceFileLoader("_rat_graph_test", str(BIN / "rat"))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        rat = importlib.util.module_from_spec(spec)
        loader.exec_module(rat)

        class FakeRevq:
            @staticmethod
            def compute_interesting(_rev):
                return [{"func": "check", "score": 10}]

        with tempfile.TemporaryDirectory() as work:
            binary = pathlib.Path(work) / "chall"
            binary.write_bytes(b"fixture")
            args = rat.build_parser().parse_args(
                ["query", "graph", str(binary), "--format", "json", "--max-nodes", "2"])
            capture = io.StringIO()
            with (patch.object(rat, "_gather_revq", return_value=(FakeRevq(), sample())),
                  patch.object(rat, "_record_revq_invocation"),
                  patch.object(rat, "_governor_wrap", side_effect=lambda _p, _k, _v, doc: doc),
                  contextlib.redirect_stdout(capture)):
                code = rat.cmd_query_graph(args)
        self.assertEqual(code, 0)
        doc = json.loads(capture.getvalue())
        validate(doc, "rat.query-result/v1")
        self.assertEqual(doc["query"], "graph")
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(doc["facts"]["visible_functions"], 2)
        self.assertEqual(doc["coverage"]["omitted"]["functions"], 1)


if __name__ == "__main__":
    unittest.main()
