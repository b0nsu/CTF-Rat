import json, os, shutil, sys, tempfile, unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))

from ratlib.desktop_analysis import AnalysisManager, resolve_target
from ratlib.run_manifest import atomic_write, new_direct


def captured(data=b"", truncated=False):
    return SimpleNamespace(preview=data, total_bytes=len(data), truncated=truncated, spool_path=None)


def result(stdout=b"", stderr=b"", exit_code=0, timed_out=False, duration_ms=7):
    return SimpleNamespace(
        stdout=captured(stdout), stderr=captured(stderr), exit_code=exit_code,
        timed_out=timed_out, duration_ms=duration_ms,
    )


class DesktopAnalysisTests(unittest.TestCase):
    def make_challenge(self, root, name="chall"):
        binary = os.path.join(root, name)
        with open(binary, "wb") as output:
            output.write(b"desktop-analysis-binary")
        manifest = new_direct("desktop-test", binary, None, None)
        atomic_write(os.path.join(root, "run.json"), manifest)
        return binary, manifest

    def brief_card(self, binary, digest):
        return {
            "schema": "rat.brief-card/v1",
            "binary": binary,
            "binary_sha256": digest,
            "capabilities": {"binutils": True, "angr": False},
            "route": {"track": "rev", "subroute": "rev-checker", "confidence": 0.8},
            "track_summary": {"entry": "main"},
            "libc": {"supplied": False},
            "truncated": [],
            "side_effects": [],
        }

    def function_result(self, name="main"):
        return {
            "schema": "rat.query-result/v1",
            "query": "func:%s" % name,
            "status": "ok",
            "facts": {"callers": ["entry"], "callees": ["check"], "strings": ["success"]},
            "heuristics": {"next": []},
            "artifacts": [],
            "coverage": {"complete": True, "scope": "func:%s" % name, "omitted": None},
            "diagnostics": [],
            "provenance": {"cache": {"hit": False}},
        }

    def test_resolve_target_uses_manifest_binary_and_rechecks_digest(self):
        with tempfile.TemporaryDirectory() as root:
            binary, manifest = self.make_challenge(root)
            target = resolve_target(root)
            self.assertEqual(target["binary"]["name"], "chall")
            self.assertEqual(target["binary"]["sha256"], manifest["inputs"][0]["sha256"])
            self.assertEqual(target["_binary_path"], os.path.realpath(binary))

            with open(binary, "ab") as output:
                output.write(b"tampered")
            with self.assertRaisesRegex(ValueError, "digest"):
                resolve_target(root)

    def test_resolve_target_rejects_manifest_path_escape(self):
        with tempfile.TemporaryDirectory() as parent:
            root = os.path.join(parent, "challenge")
            os.mkdir(root)
            outside = os.path.join(parent, "outside")
            with open(outside, "wb") as output:
                output.write(b"outside")
            manifest = new_direct("desktop-test", outside, None, None)
            manifest["inputs"][0]["name"] = "../outside"
            atomic_write(os.path.join(root, "run.json"), manifest)
            with self.assertRaisesRegex(ValueError, "basename"):
                resolve_target(root)

    def test_fast_and_deep_only_select_canonical_rat_brief_mode(self):
        with tempfile.TemporaryDirectory() as root:
            binary, manifest = self.make_challenge(root)
            card = json.dumps(self.brief_card(binary, manifest["inputs"][0]["sha256"])).encode()
            manager = AnalysisManager(root)
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((list(argv), kwargs))
                return result(stdout=card)

            with patch("ratlib.desktop_analysis.runner_run", side_effect=fake_run):
                fast = manager.brief("fast")
                deep = manager.brief("deep")

            self.assertEqual(fast["schema"], "rat.desktop.analysis-run/v1")
            self.assertEqual(fast["status"], "ok")
            self.assertEqual(deep["status"], "ok")
            self.assertEqual(calls[0][0][1:3], ["brief", os.path.realpath(binary)])
            self.assertIn("--fast", calls[0][0])
            self.assertNotIn("--fast", calls[1][0])
            for argv, kwargs in calls:
                self.assertEqual(argv[0], os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin", "rat")))
                self.assertIn("--format", argv)
                self.assertIn("json", argv)
                self.assertEqual(kwargs["cwd"], os.path.abspath(root))
                self.assertLessEqual(kwargs["max_output_bytes"], 256 * 1024)

    def test_real_fast_brief_runs_through_canonical_rat_frontdoor(self):
        source = "/bin/true"
        if not os.path.isfile(source):
            self.skipTest("requires a local ELF /bin/true fixture")
        with tempfile.TemporaryDirectory() as root:
            binary = os.path.join(root, "chall")
            shutil.copy2(source, binary)
            manifest = new_direct("desktop-real-fast", binary, None, None)
            atomic_write(os.path.join(root, "run.json"), manifest)
            doc = AnalysisManager(root).brief("fast")
            self.assertEqual(doc["status"], "ok", doc.get("diagnostic"))
            self.assertEqual(doc["result"]["schema"], "rat.brief-card/v1")
            self.assertEqual(doc["result"]["binary_sha256"], manifest["inputs"][0]["sha256"])

    def test_result_digest_must_match_manifest_input(self):
        with tempfile.TemporaryDirectory() as root:
            binary, _ = self.make_challenge(root)
            card = json.dumps(self.brief_card(binary, "sha256:" + "f" * 64)).encode()
            manager = AnalysisManager(root)
            with patch("ratlib.desktop_analysis.runner_run", return_value=result(stdout=card)):
                doc = manager.brief("fast")
            self.assertEqual(doc["status"], "error")
            self.assertIn("canonical run manifest", doc["diagnostic"])
            self.assertIsNone(doc["result"])

    def test_function_query_is_fixed_fast_bounded_rat_query(self):
        with tempfile.TemporaryDirectory() as root:
            binary, _ = self.make_challenge(root)
            payload = json.dumps(self.function_result()).encode()
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((list(argv), kwargs))
                return result(stdout=payload)

            with patch("ratlib.desktop_analysis.runner_run", side_effect=fake_run):
                doc = AnalysisManager(root).function("  main  ")
            self.assertEqual(doc["schema"], "rat.desktop.function-query/v1")
            self.assertEqual(doc["name"], "main")
            self.assertEqual(doc["status"], "ok")
            argv, kwargs = calls[0]
            self.assertEqual(argv[1:5], ["query", "func", os.path.realpath(binary), "main"])
            self.assertIn("--fast", argv)
            self.assertIn("--budget-bytes", argv)
            self.assertEqual(kwargs["timeout_seconds"], 30.0)
            self.assertLessEqual(kwargs["max_output_bytes"], 256 * 1024)

    def test_function_query_rejects_unbounded_names(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_challenge(root)
            manager = AnalysisManager(root)
            for bad in ("", "\n", "x" * 257):
                with self.assertRaises(ValueError):
                    manager.function(bad)

    def test_invalid_mode_and_unready_status_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            manager = AnalysisManager(root)
            status = manager.status()
            self.assertFalse(status["ready"])
            self.assertFalse(status["modes"]["fast"])
            self.assertFalse(status["modes"]["function"])
            self.assertTrue(status["modes"]["verify_status"])
            with self.assertRaises(ValueError):
                manager.brief("verify")

    def test_tool_failure_is_bounded_structured_result(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_challenge(root)
            manager = AnalysisManager(root)
            with patch("ratlib.desktop_analysis.runner_run", return_value=result(stderr=b"failed", exit_code=5)):
                doc = manager.brief("fast")
            self.assertEqual(doc["status"], "error")
            self.assertEqual(doc["exit_code"], 5)
            self.assertEqual(doc["diagnostic"], "failed")
            self.assertIsNone(doc["result"])


if __name__ == "__main__":
    unittest.main()
