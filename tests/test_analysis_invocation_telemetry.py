import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib import analysis, analysis_cli
from ratlib.metrics import aggregate, iter_tool_results


class AnalysisInvocationTelemetryTests(unittest.TestCase):
    def test_error_envelope_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as d:
            args = type("Args", (), {"store": d, "binary": None})()
            doc = analysis.envelope("rat-profile", None, args, {}, status="error", code=4)
            analysis_cli._persist_invocation(doc, args)
            self.assertEqual(list(iter_tool_results(d)), [])

    def _fake_command(self, argv, timeout, stdin=None, cwd=None, env=None):
        name = argv[0]
        if name == "file":
            output = "ELF 64-bit LSB executable"
        elif name == "readelf":
            output = "Type: DYN\nGNU_STACK RW\nGNU_RELRO\n UND read\n"
        elif name == "strings":
            output = "hello\nworld\n"
        else:
            self.fail("unexpected command: %r" % (argv,))
        return type("Result", (), {"stdout": type("Stream", (), {"preview": output.encode()})()})()

    def _run_profiles(self, binary, root, *extra_args):
        deps = {
            "ratlib.analysis": analysis.ANALYSIS_BUILD_DIGEST,
            "file": "sha256:file",
            "readelf": "sha256:readelf",
            "strings": "sha256:strings",
        }
        argv = ["rat-profile", binary, "--store", root, "--format", "json", *extra_args]
        with patch.object(analysis, "_profile_dependency_identity", return_value=deps), \
             patch.object(analysis, "command", side_effect=self._fake_command), \
             contextlib.redirect_stdout(io.StringIO()):
            with patch.object(sys, "argv", argv):
                self.assertEqual(analysis_cli.main("rat-profile"), 0)
            with patch.object(sys, "argv", argv):
                self.assertEqual(analysis_cli.main("rat-profile"), 0)
        return list(iter_tool_results(root))

    def test_profile_miss_and_hit_are_persisted_as_tool_result_invocations(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as f:
                f.write(b"fixture-binary")
            root = os.path.join(d, ".rat")
            docs = self._run_profiles(binary, root)

            self.assertEqual(len(docs), 2)
            self.assertEqual([d["tool"]["name"] for d in docs], ["rat-profile", "rat-profile"])
            self.assertEqual(sorted(d["cache_state"] for d in docs), ["hit", "miss"])

            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_requests"], 2)
            self.assertEqual(metrics["cache_hits"], 1)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["duplicate_tool_calls"], 0)

    def test_repeated_uncached_profile_is_counted_as_duplicate_work(self):
        with tempfile.TemporaryDirectory() as d:
            binary = os.path.join(d, "chall")
            with open(binary, "wb") as f:
                f.write(b"fixture-binary")
            root = os.path.join(d, ".rat")
            docs = self._run_profiles(binary, root, "--no-cache")

            metrics = aggregate(docs)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["cache_hits"], 0)
            self.assertEqual(metrics["cache_misses"], 2)
            self.assertEqual(metrics["duplicate_tool_calls"], 1)


if __name__ == "__main__":
    unittest.main()
