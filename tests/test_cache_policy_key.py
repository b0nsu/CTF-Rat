import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.cache import canonical_key


BINARY = "sha256:" + "a" * 64
P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64


def _old_canonical_key(**overrides):
    doc = {
        "schema": "rat.cache-key/v2",
        "binary_sha256": BINARY,
        "tool_name": "revq",
        "tool_version": "2",
        "params": {"engine": "angr"},
        "dep_versions": {"angr": "9.2.213"},
        "artifact_inputs": [],
        "output_schema": "rat.tool-result/v1",
        "analysis_schema_version": "v1",
    }
    doc.update(overrides)
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _key(policy_digest=None):
    return canonical_key(
        binary_sha256=BINARY,
        tool_name="revq",
        tool_version="2",
        params={"engine": "angr"},
        dep_versions={"angr": "9.2.213"},
        policy_digest=policy_digest,
    )


class CanonicalPolicyKeyTests(unittest.TestCase):
    def test_omitted_policy_preserves_pre_patch_key(self):
        self.assertEqual(_key(), _old_canonical_key())

    def test_policy_change_invalidates_cache_identity(self):
        self.assertNotEqual(_key(P1), _key(P2))

    def test_declared_policy_changes_identity_from_unspecified_legacy_key(self):
        self.assertNotEqual(_key(P1), _key())

    def test_same_policy_is_stable(self):
        self.assertEqual(_key(P1), _key(P1))


if __name__ == "__main__":
    unittest.main()
