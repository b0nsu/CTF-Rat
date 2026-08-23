import importlib.machinery, importlib.util, json, os, sys, tempfile, threading, time, unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin"))
sys.path.insert(0, BIN)
from ratlib.desktop_session import SessionManager

loader = importlib.machinery.SourceFileLoader("_ratd_e2e", os.path.join(BIN, "ratd"))
spec = importlib.util.spec_from_loader(loader.name, loader)
ratd = importlib.util.module_from_spec(spec)
loader.exec_module(ratd)


class DesktopE2ETests(unittest.TestCase):
    def server(self, root, argv):
        sessions = SessionManager(root, argv)
        server = ThreadingHTTPServer(("127.0.0.1", 0), ratd._handler(root, sessions))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(sessions.stop)
        return "http://127.0.0.1:%d" % server.server_port

    def read_json(self, url):
        with urlopen(Request(url), timeout=2) as response:
            self.assertEqual(response.status, 200)
            return json.loads(response.read())

    def post(self, url):
        request = Request(
            url,
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json", "X-CTF-Rat-Desktop": "1"},
        )
        with urlopen(request, timeout=2) as response:
            self.assertEqual(response.status, 200)
            return json.loads(response.read())

    def wait_finished(self, base, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            doc = self.read_json(base + "/api/session")
            if doc["status"] != "running":
                return doc
            time.sleep(0.02)
        self.fail("solver session did not finish")

    def test_solver_state_artifact_terminal_and_replay_flow(self):
        with tempfile.TemporaryDirectory() as root:
            solver_path = os.path.join(root, "solver.py")
            solver = """import sys
sys.path.insert(0, %r)
from ratlib.artifact import put_bytes
from ratlib.state_v2 import Stream

stream = Stream('.')
stream.append('hypothesis.recorded', {'hypothesis_id': 'H1', 'text': 'desktop e2e hypothesis'})
stream.append('next.recorded', {'probe': 'desktop e2e probe'})
put_bytes(
    b'{\"source\":\"desktop-e2e\"}',
    kind='desktop-e2e',
    media_type='application/json',
    logical_name='desktop-e2e.json',
    root=stream.root,
    provenance={'producer': 'desktop-e2e-test'},
)
print('desktop-e2e-terminal', flush=True)
""" % BIN
            with open(solver_path, "w", encoding="utf-8") as out:
                out.write(solver)

            base = self.server(root, [sys.executable, "-u", solver_path])
            started = self.post(base + "/api/session/start")
            self.assertTrue(started["configured"])
            finished = self.wait_finished(base)
            self.assertEqual(finished["exit_code"], 0)

            terminal = self.read_json(base + "/api/terminal?after=0&limit=4096")
            self.assertIn("desktop-e2e-terminal", terminal["text"])

            live = self.read_json(base + "/api/snapshot")
            self.assertEqual(live["cursor"]["seq"], 2)
            self.assertIn("H1", live["view"]["hypotheses"])
            self.assertEqual(live["view"]["next_probes"][-1]["probe"], "desktop e2e probe")

            events = self.read_json(base + "/api/events?after_seq=0&limit=10")
            self.assertEqual([event["seq"] for event in events["events"]], [1, 2])

            replay = self.read_json(base + "/api/snapshot?until_seq=1")
            self.assertTrue(replay["historical"])
            self.assertIn("H1", replay["view"]["hypotheses"])
            self.assertEqual(replay["view"]["next_probes"], [])

            artifacts = self.read_json(base + "/api/artifacts?limit=10")
            self.assertEqual(artifacts["total"], 1)
            artifact = artifacts["artifacts"][0]
            self.assertEqual(artifact["logical_name"], "desktop-e2e.json")
            preview = self.read_json(base + "/api/artifacts/%s?max_bytes=128" % artifact["digest"])
            self.assertEqual(preview["content"], '{"source":"desktop-e2e"}')


if __name__ == "__main__":
    unittest.main()
