import argparse, os, sys, tempfile, unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib import analysis
from ratlib.state_v2 import KNOWN_BUILD_DIGESTS


D = "sha256:" + "a" * 64


def namespace(binary):
    return argparse.Namespace(binary=binary, store=None, format="json", command=None)


class AnalysisEnvelopeIdentity(unittest.TestCase):
    def test_tool_build_digest_is_analyzer_not_subject_binary(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "challenge.bin")
            with open(binary, "wb") as f:
                f.write(b"challenge-subject")
            subject_digest = analysis.fdigest(binary)
            doc = analysis.envelope("rat-profile", binary, namespace(binary), {})
            self.assertEqual(doc["tool"]["build_digest"], analysis.ANALYSIS_BUILD_DIGEST)
            self.assertEqual(doc["inputs"][0]["digest"], subject_digest)
            self.assertNotEqual(doc["tool"]["build_digest"], subject_digest)

    def test_verify_report_has_a_domain_separated_producer_identity(self):
        self.assertNotEqual(analysis.VERIFY_BUILD_DIGEST, analysis.ANALYSIS_BUILD_DIGEST)
        doc = analysis.envelope("rat-verify", None, namespace(None), {})
        self.assertEqual(doc["tool"]["build_digest"], analysis.VERIFY_BUILD_DIGEST)

    def test_live_analyzer_build_is_recorded_for_historical_verification(self):
        self.assertEqual(
            KNOWN_BUILD_DIGESTS.get(analysis.VERIFY_BUILD_DIGEST),
            "rat-verify",
            "missing rat-verify registry entry for %s" % analysis.ANALYSIS_BUILD_DIGEST,
        )


class ProfileCacheIdentity(unittest.TestCase):
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

    def test_profile_dependency_identity_tracks_real_analyzer_inputs(self):
        deps = analysis._profile_dependency_identity()
        self.assertEqual(deps["ratlib.analysis"], analysis.ANALYSIS_BUILD_DIGEST)
        self.assertEqual(set(deps), {"ratlib.analysis", "file", "readelf", "strings"})
        for value in deps.values():
            self.assertTrue(value.startswith("sha256:") or value in {"missing", "unreadable"})


if __name__ == "__main__":
    unittest.main()
