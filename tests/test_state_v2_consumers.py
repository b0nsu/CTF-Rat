import importlib.util
import importlib.machinery
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import put_bytes
from ratlib.schema import validate
from ratlib.state_v2 import Stream, project_trusted_offsets, trusted_offset_inputs
from tests.direct_evidence_helper import direct_evidence_envelope


ROOT = pathlib.Path(__file__).resolve().parents[1]
STATE = ROOT / "bin" / "state"
PWNSTAGE = ROOT / "bin" / "pwnstage"
D = "sha256:" + "b" * 64


def pwnstage_module():
    loader = importlib.machinery.SourceFileLoader("pwnstage_under_test", str(PWNSTAGE))
    spec = importlib.util.spec_from_loader("pwnstage_under_test", loader)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def evidence(stream, name, *, level="direct", promotion_allowed=True):
    if level == "direct" and promotion_allowed:
        return direct_evidence_envelope(root=stream.root, producer="gdbq", measurement=b"measurement:" + name.encode(), summary=name)
    # Non-direct evidence is any object that is not a producer-owned verifier envelope;
    # state_v2 derives such observations as heuristic (never direct).
    return put_bytes(
        name.encode(), kind="test-evidence", media_type="text/plain",
        logical_name=name, root=stream.root,
    )["digest"]


def offset_doc(stream, oid, key="system", offset="0x50d70", *, level="direct", promotion_allowed=True):
    return {
        "schema": "rat.observation/v1",
        "observation_id": oid,
        "run_id": "run",
        "created_at": "2026-01-01T00:00:00+00:00",
        "producer": {"tool": "test", "build_digest": D},
        "subject": {"kind": "binary"},
        "kind": "pwn.offset",
        "value": {"key": key, "offset": offset},
        "evidence": [evidence(stream, oid, level=level, promotion_allowed=promotion_allowed)],
        "quality": {"level": level},
        "validity": {"state": "active"},
    }


class StateV2Consumers(unittest.TestCase):
    def run_state(self, directory, *args):
        env = dict(os.environ, CTF_HOME=directory, PYTHONPATH=str(ROOT / "bin"))
        return subprocess.run(
            [sys.executable, str(STATE), "--dir", directory, *args],
            text=True,
            capture_output=True,
            env=env,
        )

    def run_pwnstage(self, directory, *args):
        env = dict(os.environ, CTF_HOME=directory, PYTHONPATH=str(ROOT / "bin"))
        return subprocess.run(
            [sys.executable, str(PWNSTAGE), *args],
            cwd=directory,
            text=True,
            capture_output=True,
            env=env,
        )

    def test_direct_offset_projects_through_state_and_pwnstage(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            s.append("observation.recorded", offset_doc(s, "o1"))

            self.assertEqual(project_trusted_offsets(*trusted_offset_inputs(d)), {"system": 0x50D70})
            self.assertEqual(pwnstage_module().get("system", path=d), 0x50D70)

            got = self.run_state(d, "get", "system")
            self.assertEqual(got.returncode, 0, got.stderr)
            self.assertEqual(got.stdout.strip(), "0x50d70")

    def test_state_show_does_not_call_typed_offset_only_state_empty(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            s.append("observation.recorded", offset_doc(s, "o1"))

            shown = self.run_state(d, "show")
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertIn("OFFSETS (typed/direct):", shown.stdout)
            self.assertNotIn("(no v2 facts yet)", shown.stdout)

    def test_derived_invalidation_and_conflict_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            s.append("observation.recorded", offset_doc(s, "derived", level="derived", promotion_allowed=False))
            self.assertEqual(project_trusted_offsets(*trusted_offset_inputs(d)), {})

            s.append("observation.recorded", offset_doc(s, "o1"))
            s.append("evidence.invalidated", {"observation_ids": ["o1"], "reason": "bad measurement"})
            self.assertEqual(project_trusted_offsets(*trusted_offset_inputs(d)), {})

            s.append("observation.recorded", offset_doc(s, "o2", offset="0x10"))
            s.append("observation.recorded", offset_doc(s, "o3", offset="0x20"))
            with self.assertRaises(ValueError):
                project_trusted_offsets(*trusted_offset_inputs(d))

    def test_state_cli_v2_only_writes_and_legacy_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            init = self.run_state(d, "init", "chal")
            self.assertEqual(init.returncode, 0, init.stderr)
            self.assertTrue(pathlib.Path(d, ".rat", "events", "STATE.v2.jsonl").exists())
            self.assertFalse(pathlib.Path(d, "STATE.jsonl").exists())

            for args in (("offset", "system", "0x50"), ("ok", "works"), ("primitive", "rip", "candidate")):
                before = pathlib.Path(d, ".rat", "events", "STATE.v2.jsonl").read_bytes()
                result = self.run_state(d, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("STATE v2", result.stderr)
                self.assertEqual(pathlib.Path(d, ".rat", "events", "STATE.v2.jsonl").read_bytes(), before)
                self.assertFalse(pathlib.Path(d, "STATE.jsonl").exists())

            for args, typ in (
                (("hyp", "maybe overflow"), "hypothesis.recorded"),
                (("no", "fmt", "--", "not user controlled"), "route.ruled_out"),
                (("next", "decomp main"), "next.recorded"),
                (("note", "remember libc"), "note.recorded"),
                (("alert", "stale leak"), "alert.recorded"),
            ):
                result = self.run_state(d, *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(Stream(d).read()[-1]["type"], typ)

    def test_state_show_renders_ruleouts_and_next_as_nonempty_v2_state(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_state(d, "init", "chal").returncode, 0)
            self.assertEqual(self.run_state(d, "no", "qemu-user", "--", "native run works").returncode, 0)
            self.assertEqual(self.run_state(d, "next", "measure libc base").returncode, 0)

            shown = self.run_state(d, "show")
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertIn("RULED OUT:", shown.stdout)
            self.assertIn("qemu-user", shown.stdout)
            self.assertIn("NEXT:", shown.stdout)
            self.assertIn("measure libc base", shown.stdout)
            self.assertNotIn("(no v2 facts yet)", shown.stdout)

    def test_migration_diagnostic_rejects_invalid_raw_artifact_digest(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            with self.assertRaisesRegex(ValueError, "raw_artifact must be a sha256 digest"):
                s.append(
                    "migration.diagnostic",
                    {"v1_digest": D, "raw_artifact": "sha256:" + "A" * 64, "malformed_lines": [1]},
                    actor="migration",
                )

    def test_migration_diagnostic_rejects_missing_raw_artifact_object(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            missing = "sha256:" + "1" * 64
            with self.assertRaisesRegex(ValueError, "raw_artifact is missing or corrupt"):
                s.append(
                    "migration.diagnostic",
                    {"v1_digest": D, "raw_artifact": missing, "malformed_lines": [1]},
                    actor="migration",
                )

    def test_event_append_and_set_offset_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            doc = offset_doc(s, "o1")
            doc_path = pathlib.Path(d, "obs.json")
            doc_path.write_text(json.dumps(doc), encoding="utf-8")

            appended = self.run_state(d, "event", "append", str(doc_path))
            self.assertEqual(appended.returncode, 0, appended.stderr)
            self.assertEqual(pwnstage_module().offsets(path=os.path.join(d, "STATE.jsonl")), {"system": 0x50D70})

            before_v2 = pathlib.Path(d, ".rat", "events", "STATE.v2.jsonl").read_bytes()
            with self.assertRaises(ValueError):
                pwnstage_module().set_offset("system", 1, path=os.path.join(d, "STATE.jsonl"))
            self.assertEqual(pathlib.Path(d, ".rat", "events", "STATE.v2.jsonl").read_bytes(), before_v2)
            self.assertFalse(pathlib.Path(d, "STATE.jsonl").exists())

    def test_state_examples_are_schema_valid_and_candidate_first(self):
        with tempfile.TemporaryDirectory() as d:
            event = self.run_state(d, "event", "--example")
            self.assertEqual(event.returncode, 0, event.stderr)
            event_doc = json.loads(event.stdout)
            validate(event_doc, "rat.observation/v1")
            self.assertIsInstance(event_doc["evidence"][0], str)
            self.assertTrue(event_doc["evidence"][0].startswith("sha256:"))

            primitive = self.run_state(d, "primitive", "--example")
            self.assertEqual(primitive.returncode, 0, primitive.stderr)
            primitive_doc = json.loads(primitive.stdout)
            validate(primitive_doc, "rat.primitive/v1")
            self.assertEqual(primitive_doc["status"], "candidate")
            self.assertEqual(primitive_doc["self_evidence"], [])
            path = pathlib.Path(d, "primitive.json")
            path.write_text(json.dumps(primitive_doc), encoding="utf-8")
            appended = self.run_state(d, "primitive", "candidate", str(path))
            self.assertEqual(appended.returncode, 0, appended.stderr)

    def test_corrupt_trusted_offset_evidence_cli_exit2_without_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            s = Stream(d)
            doc = offset_doc(s, "o1")
            s.append("observation.recorded", doc)
            # Trust now rests on the producer-owned envelope's own bytes, so corrupt the
            # content-addressed object (a mutated metadata sidecar is simply ignored).
            # Target the observation's own cited evidence digest -- direct_evidence_envelope
            # now also writes a nested measurement artifact, so an arbitrary glob match
            # under objects/sha256 is no longer guaranteed to be the cited envelope.
            evidence_digest = doc["evidence"][0]
            h = evidence_digest[7:]
            object_file = pathlib.Path(d, ".rat", "objects", "sha256", h[:2], h[2:])
            object_file.write_text("{not json", encoding="utf-8")

            got = self.run_state(d, "get", "system")
            staged = self.run_pwnstage(d, "get", "system")
            self.assertEqual(got.returncode, 2)
            self.assertEqual(staged.returncode, 2)
            self.assertIn("trusted offset evidence artifact is missing or corrupt", got.stderr)
            self.assertIn("trusted offset evidence artifact is missing or corrupt", staged.stderr)
            self.assertNotIn("Traceback", got.stderr)
            self.assertNotIn("Traceback", staged.stderr)


if __name__ == "__main__":
    unittest.main()
