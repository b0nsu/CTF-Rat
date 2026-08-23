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

    def test_spawn_failure_preserves_terminal_log_and_cursor(self):
        with tempfile.TemporaryDirectory() as root:
            manager = SessionManager(root, [sys.executable, "-u", "-c", "print('before-failure')"])
            manager.start()
            self.wait_finished(manager)
            before = manager.log_delta(0, 4096)
            self.assertIn("before-failure", before["text"])

            manager.solver_argv = [os.path.join(root, "definitely-missing-solver")]
            with self.assertRaises(OSError):
                manager.start()

            after = manager.log_delta(0, 4096)
            self.assertEqual(after["text"], before["text"])
            self.assertEqual(after["cursor"], before["cursor"])

            manager.solver_argv = [sys.executable, "-u", "-c", "print('after-failure')"]
            manager.start()
            self.wait_finished(manager)
            resumed = manager.log_delta(before["cursor"], 4096)
            self.assertIn("after-failure", resumed["text"])

    def test_stale_cursor_survives_solver_and_daemon_restart(self):
        with tempfile.TemporaryDirectory() as root:
            first_manager = SessionManager(root, [sys.executable, "-u", "-c", "print('A'*512)"])
            first_manager.start()
            self.wait_finished(first_manager)
            first = first_manager.log_delta(0, 4096)
            old_cursor = first["cursor"]
            self.assertGreater(old_cursor, 0)

            # Reconstruct the manager to model ratd itself restarting. The
            # cursor generation must be recovered from existing session.json.
            second_payload = "BEGIN-SECOND-" + ("B" * (old_cursor + 64))
            second_manager = SessionManager(root, [sys.executable, "-u", "-c", "print(%r)" % second_payload])
            second_manager.start()
            self.wait_finished(second_manager)

            # A byte-only or non-persistent cursor would seek into this longer
            # new log and lose the prefix. Old cursors must map to offset 0.
            second = second_manager.log_delta(old_cursor, 4096)
            self.assertTrue(second["text"].startswith("BEGIN-SECOND-"))
            self.assertGreater(second["cursor"], old_cursor)


if __name__ == "__main__":
    unittest.main()
