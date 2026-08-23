import importlib.machinery, importlib.util, json, os, sys, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BIN = os.path.join(os.path.dirname(__file__), "..", "bin")
sys.path.insert(0, BIN)
from ratlib.desktop_session import SessionManager

loader = importlib.machinery.SourceFileLoader("_ratd_test", os.path.join(BIN, "ratd"))
spec = importlib.util.spec_from_loader(loader.name, loader)
ratd = importlib.util.module_from_spec(spec)
loader.exec_module(ratd)


class DesktopHttpTests(unittest.TestCase):
    def server(self, root, argv=None):
        sessions = SessionManager(root, argv)
        server = ThreadingHTTPServer(("127.0.0.1", 0), ratd._handler(root, sessions))
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
