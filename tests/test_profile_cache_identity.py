import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib import analysis


D = "sha256:" + "a" * 64


class ProfileCacheIdentityTests(unittest.TestCase):
    def _deps(self, analysis_digest):
        return {
            "ratlib.analysis": analysis_digest,
            "file": "sha256:" + "b" * 64,
            "readelf": "sha256:" + "c" * 64,
            "strings": "sha256:" + "d" * 64,
        }

    def test_analysis_code_identity_changes_profile_cache_key(self):
        environment = {"libc": None, "loader": None}
        first = analysis._profile_cache_keys(D, environment, self._deps("sha256:" + "1" * 64))
        second = analysis._profile_cache_keys(D, environment, self._deps("sha256:" + "2" * 64))
        self.assertNotEqual(first["profile"], second["profile"])
        self.assertNotEqual(first["string-index"], second["string-index"])

    def test_analysis_schema_version_changes_profile_cache_key(self):
        environment = {"libc": None, "loader": None}
        deps = self._deps("sha256:" + "1" * 64)
        first = analysis._profile_cache_keys(D, environment, deps)
        with patch.object(analysis, "PROFILE_ANALYSIS_SCHEMA", "rat-profile/test-schema"):
            second = analysis._profile_cache_keys(D, environment, deps)
        self.assertNotEqual(first["profile"], second["profile"])

    def test_profile_dependency_identity_tracks_analyzer_inputs(self):
        deps = analysis._profile_dependency_identity()
        self.assertEqual(deps["ratlib.analysis"], analysis.ANALYSIS_BUILD_DIGEST)
        self.assertEqual(set(deps), {"ratlib.analysis", "file", "readelf", "strings"})
        for value in deps.values():
            self.assertTrue(value.startswith("sha256:") or value in {"missing", "unreadable"})


if __name__ == "__main__":
    unittest.main()
