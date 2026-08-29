import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib import run_manifest


class RunManifestIdentityTests(unittest.TestCase):
    def test_explicit_revision_wins_without_git_probe(self):
        with mock.patch.dict(os.environ, {"CTF_RAT_REVISION": "release-test"}, clear=True), \
             mock.patch.object(run_manifest.subprocess, "run") as probe:
            self.assertEqual(run_manifest.ctf_rat_revision("/repo"), "release-test")
        probe.assert_not_called()

    def test_git_revision_is_used_when_checkout_is_available(self):
        revision = "a" * 40
        completed = [mock.Mock(stdout=revision + "\n"), mock.Mock(stdout=b""), mock.Mock(stdout=b"")]
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(run_manifest.subprocess, "run", side_effect=completed) as probe:
            self.assertEqual(run_manifest.ctf_rat_revision("/repo"), revision)
        self.assertEqual(probe.call_args_list[0].args[0][:4], ["git", "-C", "/repo", "rev-parse"])

    def test_dirty_checkout_is_bound_to_content_digest(self):
        revision = "a" * 40
        completed = [mock.Mock(stdout=revision + "\n"), mock.Mock(stdout=b"patch"),
                     mock.Mock(stdout=b"")]
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(run_manifest.subprocess, "run", side_effect=completed):
            identity = run_manifest.ctf_rat_revision("/repo")
        self.assertTrue(identity.startswith(revision + "+dirty.sha256:"))
        self.assertEqual(len(identity.rsplit(":", 1)[1]), 64)

    def test_git_failure_degrades_to_worktree_identity(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(run_manifest.subprocess, "run", side_effect=OSError("no git")):
            self.assertEqual(run_manifest.ctf_rat_revision("/repo"), "worktree")

    def test_new_direct_preserves_historical_worktree_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as fh:
                fh.write(b"fixture")
            with mock.patch.dict(os.environ, {}, clear=True):
                doc = run_manifest.new_direct("fixture", binary, None, None)
        self.assertEqual(doc["toolchain"]["ctf_rat_revision"], "worktree")
        self.assertEqual(doc["toolchain"]["schema_bundle"], "v1")
        self.assertEqual(doc["toolchain"]["newchal_version"], "p0-v1")
        self.assertEqual(set(doc["environment"]), {"os", "arch", "runtime"})


if __name__ == "__main__":
    unittest.main()
