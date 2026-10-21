import io
import http.client
import http.server
import os
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin"))

from ratlib.bench_artifacts import (
    ArtifactMaterializationError, _read_capped, git_blob_sha1, materialize_entry,
)
import ratlib.bench_artifacts as bench_artifacts


class BenchArtifactTests(unittest.TestCase):
    def test_http_without_interruptible_socket_fails_closed(self):
        response = object.__new__(http.client.HTTPResponse)
        response.fp = io.BytesIO(b"payload")
        with self.assertRaisesRegex(ArtifactMaterializationError, "cannot enforce"):
            _read_capped(response, 1024, deadline=time.monotonic() + 1)

    def _entry(self, payload):
        return {
            "id": "real-example-01",
            "dir": "bench/artifacts/real-example-01",
            "binary": "chall.bin",
            "fetch": {
                "url": "https://example.invalid/chall.bin",
                "git_blob_sha1": git_blob_sha1(payload),
                "license": "Apache-2.0",
            },
        }

    def test_git_blob_sha1_matches_git_object_format(self):
        self.assertEqual(
            git_blob_sha1(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )

    def test_materialize_downloads_verifies_and_marks_executable(self):
        payload = b"\x7fELF-test-payload"
        entry = self._entry(payload)

        def opener(_request, timeout=None):
            self.assertEqual(timeout, 60)
            return io.BytesIO(payload)

        with tempfile.TemporaryDirectory() as root:
            status = materialize_entry(entry, root=root, opener=opener)
            self.assertEqual(status, "downloaded")
            target = os.path.join(root, entry["dir"], entry["binary"])
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), payload)
            self.assertTrue(os.access(target, os.X_OK))

            def should_not_fetch(*_args, **_kwargs):
                raise AssertionError("verified cached artifact should not hit network")

            self.assertEqual(
                materialize_entry(entry, root=root, opener=should_not_fetch),
                "present",
            )

    def test_mismatched_download_fails_without_installing_file(self):
        payload = b"expected"
        entry = self._entry(payload)

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ArtifactMaterializationError, "digest mismatch"):
                materialize_entry(
                    entry,
                    root=root,
                    opener=lambda *_args, **_kwargs: io.BytesIO(b"tampered"),
                )
            target = os.path.join(root, entry["dir"], entry["binary"])
            self.assertFalse(os.path.exists(target))

    def test_mismatched_existing_file_fails_closed(self):
        payload = b"expected"
        entry = self._entry(payload)

        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, entry["dir"], entry["binary"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(b"wrong")
            with self.assertRaisesRegex(ArtifactMaterializationError, "digest mismatch"):
                materialize_entry(entry, root=root, opener=lambda *_args, **_kwargs: io.BytesIO(payload))
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), b"wrong")

    def test_download_is_capped_and_fails_without_installing(self):
        """R2-5: an oversized body must fail closed before verifying/installing,
        instead of reading an unbounded response into memory."""
        payload = b"\x7fELF-big"
        entry = self._entry(payload)

        class _Endless:
            """Yields more bytes than the cap on each read; never signals EOF."""
            def read(self, n=-1):
                return b"A" * (n if n and n > 0 else 65536)
            def close(self):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        with tempfile.TemporaryDirectory() as root:
            orig = bench_artifacts._MAX_ARTIFACT_BYTES
            bench_artifacts._MAX_ARTIFACT_BYTES = 256 * 1024  # small cap for the test
            self.addCleanup(setattr, bench_artifacts, "_MAX_ARTIFACT_BYTES", orig)
            with self.assertRaisesRegex(ArtifactMaterializationError, "download cap"):
                materialize_entry(entry, root=root, opener=lambda *_a, **_k: _Endless())
            target = os.path.join(root, entry["dir"], entry["binary"])
            self.assertFalse(os.path.exists(target))

    def test_slow_drip_download_fails_on_total_deadline(self):
        """#7: a source that drips bytes under the socket timeout and the byte cap
        must still fail closed once the total wall-clock budget is exceeded."""
        entry = self._entry(b"\x7fELFsmall")

        class _Drip:
            def read(self, n=-1):
                return b"X"  # one byte per read, forever, well under the cap
            def close(self):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        # Simulate wall-clock advancing 100s per monotonic() read so the deadline
        # trips without the test actually sleeping.
        base = bench_artifacts.time.monotonic()
        counter = {"t": base}

        def fake_monotonic():
            counter["t"] += 100.0
            return counter["t"]

        with tempfile.TemporaryDirectory() as root:
            orig = bench_artifacts.time.monotonic
            bench_artifacts.time.monotonic = fake_monotonic
            self.addCleanup(setattr, bench_artifacts.time, "monotonic", orig)
            with self.assertRaisesRegex(ArtifactMaterializationError, "total time budget"):
                materialize_entry(entry, root=root, opener=lambda *_a, **_k: _Drip(),
                                  timeout=60, total_timeout=300)
            target = os.path.join(root, entry["dir"], entry["binary"])
            self.assertFalse(os.path.exists(target))

    def test_live_chunked_drip_stops_within_total_deadline(self):
        entry = self._entry(b"expected")

        class DripHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"1\r\nX\r\n")
                        self.wfile.flush()
                        time.sleep(0.02)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DripHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        entry["fetch"]["url"] = "http://127.0.0.1:%d/chall.bin" % server.server_port
        try:
            with tempfile.TemporaryDirectory() as root:
                start = time.monotonic()
                with self.assertRaisesRegex(ArtifactMaterializationError, "total time budget"):
                    materialize_entry(entry, root=root, timeout=1, total_timeout=0.2)
                self.assertLess(time.monotonic() - start, 1.0)
        finally:
            server.shutdown()
            server.server_close()

    def test_live_http_download_installs_pinned_payload(self):
        payload = b"\x7fELF-live-worker"
        entry = self._entry(payload)
        received_user_agents = []

        class PayloadHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received_user_agents.append(self.headers.get("User-Agent"))
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PayloadHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        entry["fetch"]["url"] = "http://127.0.0.1:%d/chall.bin" % server.server_port
        try:
            with tempfile.TemporaryDirectory() as root:
                self.assertEqual(materialize_entry(entry, root=root, timeout=2,
                                                   total_timeout=2), "downloaded")
                target = os.path.join(root, entry["dir"], entry["binary"])
                with open(target, "rb") as source:
                    self.assertEqual(source.read(), payload)
                self.assertEqual(received_user_agents, ["CTF-Rat-ratbench/1"])
        finally:
            server.shutdown()
            server.server_close()

    def test_slow_http_headers_stop_within_total_deadline(self):
        entry = self._entry(b"expected")
        headers_started = threading.Event()

        class SlowHeaders(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    self.wfile.flush()
                    headers_started.set()
                    for _ in range(75):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                        time.sleep(0.02)
                    self.wfile.write(b"\r\nContent-Length: 8\r\n\r\n")
                    self.wfile.write(b"expected")
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowHeaders)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        entry["fetch"]["url"] = "http://127.0.0.1:%d/chall.bin" % server.server_port
        try:
            with tempfile.TemporaryDirectory() as root:
                start = time.monotonic()
                with self.assertRaisesRegex(ArtifactMaterializationError, "total time budget"):
                    materialize_entry(entry, root=root, timeout=2, total_timeout=0.5)
                self.assertTrue(headers_started.is_set(), "the fetch must reach HTTP headers")
                self.assertLess(time.monotonic() - start, 1.2)
                target = os.path.join(root, entry["dir"], entry["binary"])
                self.assertFalse(os.path.exists(target))
        finally:
            server.shutdown()
            server.server_close()

    def test_oversized_existing_file_is_rejected_before_read(self):
        """Codex P2: an already-materialized target larger than the cap must fail
        closed on size, not be read whole into memory before the digest check."""
        payload = b"\x7fELF-small"
        entry = self._entry(payload)
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, entry["dir"], entry["binary"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            orig = bench_artifacts._MAX_ARTIFACT_BYTES
            bench_artifacts._MAX_ARTIFACT_BYTES = 1024  # small cap for the test
            self.addCleanup(setattr, bench_artifacts, "_MAX_ARTIFACT_BYTES", orig)
            with open(target, "wb") as fh:
                fh.write(b"B" * 4096)  # pre-existing file over the cap

            def should_not_fetch(*_a, **_k):
                raise AssertionError("must fail on size before any fetch")

            with self.assertRaisesRegex(ArtifactMaterializationError, "exceeds"):
                materialize_entry(entry, root=root, opener=should_not_fetch)

    def test_symlinked_fixture_dir_cannot_escape_store_root(self):
        """A fixture dir that is a symlink out of the store root must be refused,
        and nothing may be written to the external target."""
        payload = b"\x7fELF-escape-payload"
        entry = {
            "id": "escape-01",
            "dir": "bench/artifacts/escape-01",
            "binary": "chall.bin",
            "fetch": {
                "url": "https://example.invalid/chall.bin",
                "git_blob_sha1": git_blob_sha1(payload),
                "license": "Apache-2.0",
            },
        }
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            link_path = os.path.join(root, "bench", "artifacts", "escape-01")
            os.makedirs(os.path.dirname(link_path), exist_ok=True)
            os.symlink(outside, link_path)  # fixture dir points outside the store root

            def should_not_fetch(*_args, **_kwargs):
                raise AssertionError("escape attempt must fail before any network access")

            with self.assertRaisesRegex(ArtifactMaterializationError, "escape"):
                materialize_entry(entry, root=root, opener=should_not_fetch)
            # No file written into the external directory.
            self.assertEqual(os.listdir(outside), [])


if __name__ == "__main__":
    unittest.main()
