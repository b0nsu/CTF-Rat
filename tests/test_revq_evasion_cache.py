import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import unittest

BIN = os.path.join(os.path.dirname(__file__), "..", "bin")
sys.path.insert(0, BIN)


def load_revq_module():
    path = os.path.join(BIN, "revq")
    loader = importlib.machinery.SourceFileLoader("_test_revq_evasion_cache", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RevqEvasionCacheTests(unittest.TestCase):
    def test_legacy_sidecar_is_recomputed_then_current_sidecar_hits(self):
        revq = load_revq_module()
        with tempfile.TemporaryDirectory() as tempdir:
            binary = os.path.join(tempdir, "chall")
            with open(binary, "wb") as fh:
                fh.write(b"synthetic-binary-for-cache-contract")
            digest = revq.sha256(binary)
            sidecar = revq.cache_path(binary)

            legacy = {
                "schema": revq.SCHEMA,
                "engine": "binutils",
                "arch": "amd64",
                "pie": False,
                "stripped": False,
                "functions": [],
                "strings": [],
                "imports": [],
                "analysis_complete": False,
                "functions_filtered": 0,
                "evasion": ["패커 섹션 UPX0"],
                "platform": "elf",
                "bin": binary,
                "sha256": digest,
            }
            with open(sidecar, "w", encoding="utf-8") as fh:
                json.dump(legacy, fh)

            calls = []

            def fresh_extract(_binary):
                calls.append(_binary)
                return {
                    "schema": revq.SCHEMA,
                    "engine": "binutils",
                    "arch": "amd64",
                    "pie": False,
                    "stripped": False,
                    "functions": [],
                    "strings": [],
                    "imports": [],
                    "analysis_complete": False,
                    "functions_filtered": 0,
                    "evasion_signal_schema": revq.EVASION_SIGNAL_SCHEMA,
                    "evasion_signals": [
                        {"kind": "packer-section", "value": {"section": "UPX0"}, "quality": "fact"}
                    ],
                    "evasion": ["패커 섹션 UPX0"],
                    "platform": "elf",
                }

            revq.extract_binutils = fresh_extract
            revq._canonical_index = lambda *args, **kwargs: (None, None)

            first = revq.load_or_extract(binary, "binutils", False)
            self.assertEqual(calls, [binary])
            self.assertEqual(first["cache_state"], "miss")
            self.assertEqual(first["evasion_signal_schema"], revq.EVASION_SIGNAL_SCHEMA)

            with open(sidecar, encoding="utf-8") as fh:
                persisted = json.load(fh)
            self.assertEqual(persisted["evasion_signal_schema"], revq.EVASION_SIGNAL_SCHEMA)
            self.assertEqual(persisted["evasion_signals"][0]["kind"], "packer-section")

            def should_not_extract(_binary):
                raise AssertionError("current typed sidecar should have been a cache hit")

            revq.extract_binutils = should_not_extract
            second = revq.load_or_extract(binary, "binutils", False)
            self.assertEqual(second["cache_state"], "hit")
            self.assertEqual(second["evasion_signals"], persisted["evasion_signals"])


if __name__ == "__main__":
    unittest.main()
