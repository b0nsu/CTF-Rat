import importlib.machinery, importlib.util, json, os, sys, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BIN = os.path.join(os.path.dirname(__file__), "..", "bin")
sys.path.insert(0, BIN)
from ratlib.artifact import put_bytes
from ratlib.desktop_session import SessionManager
from ratlib.state_v2 import Stream

loader = importlib.machinery.SourceFileLoader("_ratd_test", os.path.join(BIN, "ratd"))
spec = importlib.util.spec_from_loader(loader.name, loader)
ratd = importlib.util.module_from_spec(spec)
loader.exec_module(ratd)


class FakeAnalysis:
    def __init__(self):
        self.calls = []

    def status(self):
        return {
            "schema": "rat.desktop.analysis-status/v1",
            "ready": True,
            "busy": False,
            "target": {"binary": {"name": "chall", "sha256": "sha256:" + "1" * 64, "size": 1}},
            "modes": {"fast": True, "deep": True, "function": True, "verify_status": True},
            "reason": None,
        }

    def brief(self, mode):
        self.calls.append(("brief", mode))
        return {
            "schema": "rat.desktop.analysis-run/v1",
            "mode": mode,
            "status": "ok",
            "target": self.status()["target"],
            "duration_ms": 1,
            "exit_code": 0,
            "result": {"schema": "rat.brief-card/v1", "binary": "chall", "capabilities": {}, "route": {}, "track_summary": {}, "libc": {}, "truncated": [], "side_effects": []},
            "diagnostic": None,
        }

    def function(self, name):
        self.calls.append(("function", name))
        return {
            "schema": "rat.desktop.function-query/v1",
            "name": name,
            "status": "ok",
            "target": self.status()["target"],
            "duration_ms": 1,
            "exit_code": 0,
            "result": {"schema": "rat.query-result/v1", "query": "func:" + name, "status": "ok", "facts": {}, "heuristics": {}, "artifacts": [], "coverage": {"complete": True, "scope": "func:" + name, "omitted": None}, "diagnostics": [], "provenance": {"cache": {"hit": False}}},
            "diagnostic": None,
        }


class DesktopHttpTests(unittest.TestCase):
    def server(self, root, argv=None, analyses=None):
        sessions = SessionManager(root, argv)
        server = ThreadingHTTPServer(("127.0.0.1", 0), ratd._handler(root, sessions, analyses))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(sessions.stop)
        return "http://127.0.0.1:%d" % server.server_port

    def read_json(self, request):
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())

    def test_health_allows_non_browser_loopback_client(self):
        with tempfile.TemporaryDirectory() as root:
            base = self.server(root)
            status, doc = self.read_json(Request(base + "/api/health"))
            self.assertEqual(status, 200)
            self.assertEqual(doc["status"], "ok")
            self.assertFalse(doc["session"]["configured"])

    def test_analysis_status_and_brief_expose_only_bounded_modes(self):
        with tempfile.TemporaryDirectory() as root:
            analyses = FakeAnalysis()
            base = self.server(root, analyses=analyses)
            status, doc = self.read_json(Request(base + "/api/analysis/status"))
            self.assertEqual(status, 200)
            self.assertTrue(doc["ready"])
            self.assertNotIn("_binary_path", json.dumps(doc))

            headers = {"Content-Type": "application/json", "X-CTF-Rat-Desktop": "1"}
            status, doc = self.read_json(Request(
                base + "/api/analysis/brief", data=b'{"mode":"fast"}', method="POST", headers=headers
            ))
            self.assertEqual(status, 200)
            self.assertEqual(doc["mode"], "fast")
            self.assertEqual(analyses.calls, [("brief", "fast")])

            for body in (b'{"mode":"verify"}', b'{"mode":"fast","argv":["/bin/sh"]}', b'{"binary":"/bin/sh","mode":"fast"}'):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(base + "/api/analysis/brief", data=body, method="POST", headers=headers), timeout=2)
                self.assertEqual(caught.exception.code, 400)
            self.assertEqual(analyses.calls, [("brief", "fast")])

    def test_function_query_accepts_only_one_name_field(self):
        with tempfile.TemporaryDirectory() as root:
            analyses = FakeAnalysis()
            base = self.server(root, analyses=analyses)
            headers = {"Content-Type": "application/json", "X-CTF-Rat-Desktop": "1"}
            status, doc = self.read_json(Request(
                base + "/api/analysis/function", data=b'{"name":"main"}', method="POST", headers=headers
            ))
            self.assertEqual(status, 200)
            self.assertEqual(doc["name"], "main")
            self.assertEqual(analyses.calls, [("function", "main")])
            for body in (b'{"name":"main","binary":"/bin/sh"}', b'{"name":"main","argv":["sh"]}', b'{"name":1}'):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(base + "/api/analysis/function", data=body, method="POST", headers=headers), timeout=2)
                self.assertEqual(caught.exception.code, 400)
            self.assertEqual(analyses.calls, [("function", "main")])

    def test_event_generation_hint_round_trips_over_http(self):
        with tempfile.TemporaryDirectory() as root:
            Stream(root).append("hypothesis.recorded", {"hypothesis_id": "H1"})
            base = self.server(root)
            status, first = self.read_json(Request(base + "/api/events?after_seq=0&limit=10"))
            self.assertEqual(status, 200)
            cursor = first["cursor"]
            self.assertIsInstance(cursor["source_generation"], str)
            params = urlencode({
                "after_seq": cursor["seq"],
                "limit": 10,
                "stream_id": cursor["stream_id"],
                "known_generation": cursor["source_generation"],
            })
            status, unchanged = self.read_json(Request(base + "/api/events?" + params))
            self.assertEqual(status, 200)
            self.assertTrue(unchanged["unchanged"])
            self.assertFalse(unchanged["reset"])
            self.assertEqual(unchanged["events"], [])
            self.assertEqual(unchanged["cursor"], cursor)

    def test_live_projection_returns_snapshot_on_change_and_none_when_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            Stream(root).append("hypothesis.recorded", {"hypothesis_id": "H1"})
            base = self.server(root)
            status, first = self.read_json(Request(base + "/api/live?after_seq=0&limit=10"))
            self.assertEqual(status, 200)
            self.assertEqual(first["schema"], "rat.desktop.live/v1")
            self.assertIsNotNone(first["snapshot"])
            self.assertEqual(first["snapshot"]["cursor"]["seq"], 1)
            cursor = first["delta"]["cursor"]
            params = urlencode({
                "after_seq": cursor["seq"],
                "limit": 10,
                "stream_id": cursor["stream_id"],
                "known_generation": cursor["source_generation"],
            })
            status, unchanged = self.read_json(Request(base + "/api/live?" + params))
            self.assertEqual(status, 200)
            self.assertTrue(unchanged["delta"]["unchanged"])
            self.assertIsNone(unchanged["snapshot"])

    def test_completion_endpoint_uses_canonical_gate(self):
        with tempfile.TemporaryDirectory() as root:
            base = self.server(root)
            status, doc = self.read_json(Request(base + "/api/completion"))
            self.assertEqual(status, 200)
            self.assertEqual(doc["schema"], "rat.desktop.completion/v1")
            self.assertFalse(doc["verified"])
            self.assertEqual(doc["reason"], "no-active-primitive")

    def test_telemetry_endpoint_includes_v21_session_metrics(self):
        with tempfile.TemporaryDirectory() as root:
            Stream(root).append("hypothesis.recorded", {"hypothesis_id": "H1"})
            base = self.server(root)
            status, doc = self.read_json(Request(base + "/api/telemetry"))
            self.assertEqual(status, 200)
            self.assertEqual(doc["schema"], "rat.desktop.telemetry/v1")
            self.assertEqual(doc["event_count"], 1)
            self.assertEqual(doc["session"]["schema"], "rat.session-metrics/v1")

    def test_artifact_generation_hint_round_trips_over_http(self):
        with tempfile.TemporaryDirectory() as root:
            stream = Stream(root)
            put_bytes(
                b"desktop-artifact",
                kind="test",
                media_type="application/octet-stream",
                logical_name="artifact.bin",
                root=stream.root,
            )
            base = self.server(root)
            status, first = self.read_json(Request(base + "/api/artifacts?limit=10"))
            self.assertEqual(status, 200)
            self.assertFalse(first["unchanged"])
            self.assertEqual(first["total"], 1)
            params = urlencode({"limit": 10, "known_generation": first["generation"]})
            status, unchanged = self.read_json(Request(base + "/api/artifacts?" + params))
            self.assertEqual(status, 200)
            self.assertTrue(unchanged["unchanged"])
            self.assertEqual(unchanged["artifacts"], [])
            self.assertIsNone(unchanged["total"])

    def test_disallowed_browser_origin_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            base = self.server(root)
            request = Request(base + "/api/snapshot", headers={"Origin": "https://attacker.example"})
            with self.assertRaises(HTTPError) as caught:
                urlopen(request, timeout=2)
            self.assertEqual(caught.exception.code, 403)

    def test_control_header_is_required(self):
        with tempfile.TemporaryDirectory() as root:
            base = self.server(root, [sys.executable, "-u", "-c", "print('ok')"])
            request = Request(base + "/api/session/start", data=b"{}", method="POST", headers={"Content-Type": "application/json"})
            with self.assertRaises(HTTPError) as caught:
                urlopen(request, timeout=2)
            self.assertEqual(caught.exception.code, 403)

    def test_start_uses_only_daemon_configured_argv(self):
        with tempfile.TemporaryDirectory() as root:
            configured = [sys.executable, "-u", "-c", "print('configured-only')"]
            base = self.server(root, configured)
            headers = {"Content-Type": "application/json", "X-CTF-Rat-Desktop": "1"}
            status, doc = self.read_json(Request(base + "/api/session/start", data=b"{}", method="POST", headers=headers))
            self.assertEqual(status, 200)
            self.assertEqual(doc["argv"], configured)
            override = json.dumps({"argv": ["/bin/sh"]}).encode()
            with self.assertRaises(HTTPError) as caught:
                urlopen(Request(base + "/api/session/start", data=override, method="POST", headers=headers), timeout=2)
            self.assertEqual(caught.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
