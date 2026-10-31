"""Small operational contracts from the remediation plan."""
import importlib.machinery
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.state_v2 import Stream, revise_primitive


class FollowupOperationalRepairs(unittest.TestCase):
    def test_candidate_revision_and_cursor_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = Stream(directory)
            base = {"schema": "rat.primitive/v1", "primitive_id": "p",
                    "name": "test candidate", "class": "control-flow", "status": "candidate",
                    "input_digest": "sha256:" + "1" * 64,
                    "environment_digest": "sha256:" + "2" * 64,
                    "self_evidence": [], "constraints": [], "side_effects": [],
                    "remote_equivalent": False, "producer": {"tool": "test", "version": "1"},
                    "revision": 1}
            revise_primitive(stream, base)
            revise_primitive(stream, {**base, "revision": 2, "constraints": ["new observation needed"]})
            self.assertEqual(stream.view()["primitives"]["p"]["revision"], 2)
            current = stream.read()[-1]
            for bad in (1, "bad", {}, {"stream_id": current["stream_id"], "seq": True},
                        {"stream_id": "wrong", "seq": 0}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    stream.delta(after=bad)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                stream.delta(after={"stream_id": current["stream_id"], "seq": 2},
                             until={"stream_id": current["stream_id"], "seq": 1})
            for cursor in ("1", "{bad", '{}'):
                run = subprocess.run([str(ROOT / "bin/state"), "delta", "--after", cursor],
                                     cwd=directory, text=True, capture_output=True)
                self.assertEqual(run.returncode, 2, run.stderr)
                self.assertIn("[state:err]", run.stderr)

    def test_pwngadget_arch_defaults_to_detected_elf(self):
        path = ROOT / "bin/pwngadget"
        loader = importlib.machinery.SourceFileLoader("pwngadget_arch_test", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "arm"
            binary.write_bytes(b"\x7fELF\x01\x01" + b"\0" * 10 + b"\x02\0\x28\0")
            with mock.patch.object(module, "query_binary", return_value=0) as query:
                self.assertEqual(module.main([str(binary), "ret"]), 0)
                self.assertEqual(query.call_args.args[2], "arm")
            unknown = pathlib.Path(directory) / "unknown"
            unknown.write_bytes(b"not an elf")
            with self.assertRaises(SystemExit) as result:
                module.main([str(unknown), "ret"])
            self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
