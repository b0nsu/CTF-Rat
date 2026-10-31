"""pwnflag records a synthetic remote transcript as attestable evidence."""
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.state_v2 import Stream, rat_dir  # noqa: E402
from ratlib.artifact import get  # noqa: E402


def _load_pwnflag():
    path = str(ROOT / "bin" / "pwnflag")
    loader = importlib.machinery.SourceFileLoader("pwnflag_mod", path)
    spec = importlib.util.spec_from_loader("pwnflag_mod", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


PWNFLAG = _load_pwnflag()


class PwnflagRecordTests(unittest.TestCase):
    def _home(self, stack):
        home = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
        (home / "solve" / "fixture").mkdir(parents=True)
        return home

    def _run(self, home, **kw):
        args = type("A", (), kw)()
        with mock.patch.dict(os.environ, {"CTF_HOME": str(home)}):
            return PWNFLAG.cmd_record(args)

    def test_records_transcript_and_mints_heuristic_pwn_flag(self):
        import contextlib
        with contextlib.ExitStack() as stack:
            home = self._home(stack)
            flag = "DH{1c78f751:example}"
            transcript = b"$ cat flag\n" + flag.encode() + b"\n"
            tpath = home / "transcript.log"
            tpath.write_bytes(transcript)
            message, code = self._run(home, chal="fixture", flag=flag,
                                      remote="fixture.example.invalid:12345",
                                      transcript=str(tpath))
            self.assertIsNone(message, message)
            self.assertEqual(code, 0)

            chal_dir = str(home / "solve" / "fixture")
            view = Stream(chal_dir).view()
            observations = view["observations"]
            flags = [o for o in observations.values() if o.get("kind") == "pwn.flag"]
            self.assertEqual(len(flags), 1)
            obs = flags[0]
            # The evidence digest is present and the transcript round-trips.
            digest = obs["value"]["transcript_digest"]
            self.assertEqual(get(digest, root=rat_dir(chal_dir)), transcript)
            self.assertIn(digest, obs["evidence"])
            self.assertEqual(obs["value"]["flag"], flag)
            # A remote transcript is NOT direct evidence: the Stream re-derives
            # quality from the bytes and keeps it heuristic.
            self.assertEqual(obs["quality"]["level"], "heuristic")
            self.assertEqual(obs["validity"]["state"], "active")

    def test_refuses_placeholder_flag(self):
        import contextlib
        with contextlib.ExitStack() as stack:
            home = self._home(stack)
            tpath = home / "t.log"
            tpath.write_bytes(b"FLAG{fakeflag}\n")
            message, code = self._run(home, chal="fixture", flag="FLAG{fakeflag}",
                                      remote="h:1", transcript=str(tpath))
            self.assertEqual(code, 1)
            self.assertIn("verdict", message)
            self.assertEqual(Stream(str(home / "solve" / "fixture")).view()["observations"], {})

    def test_refuses_when_transcript_lacks_flag(self):
        import contextlib
        with contextlib.ExitStack() as stack:
            home = self._home(stack)
            tpath = home / "t.log"
            tpath.write_bytes(b"shell opened but no flag text here\n")
            message, code = self._run(home, chal="fixture", flag="DH{real:aGVsbG8=}",
                                      remote="h:1", transcript=str(tpath))
            self.assertEqual(code, 1)
            self.assertIn("does not contain the claimed flag", message)
            self.assertEqual(Stream(str(home / "solve" / "fixture")).view()["observations"], {})

    def test_refuses_missing_challenge_dir(self):
        import contextlib
        with contextlib.ExitStack() as stack:
            home = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
            (home / "solve").mkdir()
            tpath = home / "t.log"
            tpath.write_bytes(b"DH{x:y}\n")
            with self.assertRaises(SystemExit):
                self._run(home, chal="nope", flag="DH{x:y}", remote="h:1", transcript=str(tpath))


if __name__ == "__main__":
    unittest.main()
