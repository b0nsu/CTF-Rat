import importlib.machinery
import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(ROOT, "bin")


def _load_revq():
    loader = importlib.machinery.SourceFileLoader("_revq_effective_engine", os.path.join(BIN, "revq"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


REVQ = _load_revq()


def _minimal(engine):
    return {
        "schema": REVQ.SCHEMA,
        "engine": engine,
        "functions": [],
        "strings": [],
        "imports": [],
    }


class EffectiveEngineIdentityTests(unittest.TestCase):
    def test_angr_sidecar_reused_for_binutils_request_indexes_as_angr(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as f:
                f.write(b"fixture")
            rev = _minimal("angr")
            rev["sha256"] = REVQ.sha256(binary)
            with open(REVQ.cache_path(binary), "w", encoding="utf-8") as f:
                json.dump(rev, f)

            seen = []
            def capture(_binary, engine, _sha, _root=None):
                seen.append(engine)
                return None, None

            with mock.patch.object(REVQ, "_canonical_index", side_effect=capture):
                out = REVQ.load_or_extract(binary, "binutils", False, index_root=os.path.join(d, ".rat"))

            self.assertEqual(out["engine"], "angr")
            self.assertEqual(seen, ["angr"])

    def test_fresh_binutils_extract_indexes_as_binutils(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as f:
                f.write(b"fixture")
            seen = []
            def capture(_binary, engine, _sha, _root=None):
                seen.append(engine)
                return None, None

            with mock.patch.object(REVQ, "extract_binutils", return_value=_minimal("binutils")), \
                 mock.patch.object(REVQ, "_canonical_index", side_effect=capture):
                out = REVQ.load_or_extract(binary, "binutils", False, index_root=os.path.join(d, ".rat"))

            self.assertEqual(out["engine"], "binutils")
            self.assertEqual(seen, ["binutils"])


if __name__ == "__main__":
    unittest.main()
