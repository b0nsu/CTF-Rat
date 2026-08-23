import os, sys, tempfile, time, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.desktop_session import SessionManager


class DesktopSessionTests(unittest.TestCase):
    def wait_finished(self, manager, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = manager.status()
            if status["status"] != "running":
                return status
            time.sleep(0.02)
        self.fail("session did not finish")

    def test_unconfigured_session_is_idle(self):
        with tempfile.TemporaryDirectory() as root:
            manager = SessionManager(root, None)
            self.assertFalse(manager.status()["configured"])
            with self.assertRaises(ValueError):
                manager.start()

    def test_session_captures_pty_output_and_replays_by_offset(self):
        with tempfile.TemporaryDirectory() as root:
            manager = SessionManager(root, [sys.executable, "-u", "-c", "print('hello-desktop')"])
            started = manager.start()
            self.assertIsNotNone(started["session_id"])
            self.assertIn(started["status"], {"running", "finished"})
            finished = self.wait_finished(manager)
            self.assertEqual(finished["exit_code"], 0)
            log = manager.log_delta(0, 1024)
            self.assertIn("hello-desktop", log["text"])
            tail = manager.log_delta(log["cursor"], 1024)
            self.assertEqual(tail["text"], "")

    def test_terminal_input_is_bounded_and_sent_to_configured_process(self):
        with tempfile.TemporaryDirectory() as root:
            code = "value=input(); print('ECHO:'+value, flush=True)"
            manager = SessionManager(root, [sys.executable, "-u", "-c", code])
            manager.start()
            manager.write("rat\n")
            self.wait_finished(manager)
            self.assertIn("ECHO:rat", manager.log_delta(0, 4096)["text"])
            with self.assertRaises(ValueError):
                manager.write("x" * 5000)

    def test_stop_terminates_process_group(self):
        with tempfile.TemporaryDirectory() as root:
            manager = SessionManager(root, [sys.executable, "-u", "-c", "import time; print('ready', flush=True); time.sleep(30)"])
            manager.start()
            time.sleep(0.05)
            stopped = manager.stop(grace_seconds=0.1)
            self.assertEqual(stopped["status"], "finished")
            self.assertIsNotNone(stopped["exit_code"])

    def test_rapid_restart_starts_with_fresh_terminal_log(self):
        with tempfile.TemporaryDirectory() as root:
            manager = SessionManager(root, [sys.executable, "-u", "-c", "print('first')"])
            manager.start()
            self.wait_finished(manager)
            self.assertIn("first", manager.log_delta(0, 4096)["text"])
            manager.solver_argv = [sys.executable, "-u", "-c", "print('second')"]
            manager.start()
            self.wait_finished(manager)
            replay = manager.log_delta(0, 4096)["text"]
            self.assertIn("second", replay)
            self.assertNotIn("first", replay)


if __name__ == "__main__":
    unittest.main()
