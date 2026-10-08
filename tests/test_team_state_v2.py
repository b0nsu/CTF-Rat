import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
from ratlib.artifact import put_bytes
from ratlib import team_state_store as store
from ratlib.state_v2 import Stream
from tests.direct_evidence_helper import direct_evidence_envelope


ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "c" * 64


def offset_doc(stream, oid, key="system", value="0x50d70"):
    evidence = direct_evidence_envelope(root=stream.root, producer="gdbq", measurement=b"measurement:" + oid.encode(), summary="evidence " + oid)
    return {
        "schema": "rat.observation/v1",
        "observation_id": oid,
        "run_id": "team-test",
        "created_at": "2026-01-01T00:00:00+00:00",
        "producer": {"tool": "test", "build_digest": DIGEST},
        "subject": {"kind": "binary"},
        "kind": "pwn.offset",
        "value": {"key": key, "offset": value},
        "evidence": [evidence],
        "quality": {"level": "direct"},
        "validity": {"state": "active"},
    }


def artifact_exists(root, digest):
    h = digest[7:]
    return pathlib.Path(root, "objects", "sha256", h[:2], h[2:]).exists() and pathlib.Path(
        root, "metadata", "sha256", h[:2], h[2:] + ".json"
    ).exists()


def first_artifact_paths(root):
    meta = sorted(pathlib.Path(root, "metadata", "sha256").glob("*/*.json"))[0]
    digest = json.loads(meta.read_text(encoding="utf-8"))["digest"]
    h = digest[7:]
    obj = pathlib.Path(root, "objects", "sha256", h[:2], h[2:])
    return obj, meta


class TeamStateV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.ctf_home = self.root / "ctf"
        self.team = self.root / "team"
        (self.ctf_home / "solve").mkdir(parents=True)
        self.team.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.team, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.team, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.team, check=True)
        (self.team / ".author").write_text("alice\n", encoding="utf-8")
        self.env = dict(os.environ, CTF_HOME=str(self.ctf_home), CTF_TEAM=str(self.team), PYTHONPATH=str(ROOT / "bin"))

    def tearDown(self):
        self.tmp.cleanup()

    def make_challenge(self, name="chal", value="0x50d70"):
        chal = self.ctf_home / "solve" / name
        chal.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(chal / ".rat", ignore_errors=True)
        stream = Stream(str(chal))
        stream.append("run.initialized", {"challenge": name})
        stream.append("observation.recorded", offset_doc(stream, "obs_" + name, value=value))
        return chal

    def make_snapshot_from_rat(self, name, author, rat_dir, events):
        current = "%s-%d" % (events[-1]["stream_id"], events[-1]["seq"])
        author_root = self.team / "chals" / name / "state-v2" / author
        snapshot = author_root / "snapshots" / current
        shutil.copytree(rat_dir, snapshot / ".rat")
        (author_root / "CURRENT").write_text(current + "\n", encoding="utf-8")
        return snapshot

    def run_tool(self, name, *args):
        return subprocess.run([str(ROOT / "bin" / name), *args], env=self.env, text=True, capture_output=True)

    def run_tool_with_env(self, env, name, *args):
        return subprocess.run([str(ROOT / "bin" / name), *args], env=env, text=True, capture_output=True)

    def committed_paths(self):
        listed = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD"],
            cwd=self.team,
            text=True,
            capture_output=True,
            check=True,
        )
        return set(listed.stdout.splitlines())

    def committed_text(self, path):
        shown = subprocess.run(
            ["git", "show", "HEAD:" + path],
            cwd=self.team,
            text=True,
            capture_output=True,
            check=True,
        )
        return shown.stdout

    def commit_ignore_rat(self):
        (self.team / ".gitignore").write_text("**/.rat/\n", encoding="utf-8")
        subprocess.run(["git", "add", ".gitignore"], cwd=self.team, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "ignore rat internals"], cwd=self.team, check=True)

    def latest_snapshot_relpath(self, name="chal", author="alice"):
        author_root = self.team / "chals" / name / "state-v2" / author
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        return "chals/%s/state-v2/%s/snapshots/%s" % (name, author, current)

    def assert_committed_snapshot_closure(self, snapshot):
        paths = self.committed_paths()
        self.assertIn(snapshot + "/PUBLICATION.json", paths)
        self.assertIn(snapshot + "/.rat/events/STATE.v2.jsonl", paths)
        self.assertIn(snapshot + "/.rat/objects/sha256", "\n".join(paths))
        self.assertIn(snapshot + "/.rat/metadata/sha256", "\n".join(paths))

    def assert_committed_digest(self, snapshot, digest):
        h = digest[7:]
        paths = self.committed_paths()
        self.assertIn(snapshot + "/.rat/objects/sha256/%s/%s" % (h[:2], h[2:]), paths)
        self.assertIn(snapshot + "/.rat/metadata/sha256/%s/%s.json" % (h[:2], h[2:]), paths)

    def publication_path(self, name="chal", author="alice"):
        snapshot = self.latest_snapshot_relpath(name, author)
        return self.team / snapshot / "PUBLICATION.json"

    def mutate_publication(self, mutator, name="chal", author="alice"):
        path = self.publication_path(name, author)
        doc = json.loads(path.read_text(encoding="utf-8"))
        mutator(doc)
        path.write_text(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        return path

    def fake_git_env(self, script):
        fakebin = self.root / "fakebin"
        fakebin.mkdir(exist_ok=True)
        git = fakebin / "git"
        git.write_text(script, encoding="utf-8")
        git.chmod(0o755)
        return dict(self.env, PATH=str(fakebin) + os.pathsep + self.env.get("PATH", ""))

    def hold_repo_lock(self):
        locked = self.root / "repo.locked"
        release = self.root / "repo.release"
        code = (
            "import os, pathlib, sys, time\n"
            "sys.path.insert(0, %r)\n"
            "from ratlib import team_state_store as store\n"
            "repo = %r\n"
            "locked = pathlib.Path(%r)\n"
            "release = pathlib.Path(%r)\n"
            "with store.repo_lock(repo):\n"
            "    locked.write_text('locked\\n', encoding='utf-8')\n"
            "    while not release.exists():\n"
            "        time.sleep(0.02)\n"
        ) % (str(ROOT / "bin"), str(self.team), str(locked), str(release))
        proc = subprocess.Popen([sys.executable, "-c", code], env=self.env)
        deadline = time.time() + 5
        while time.time() < deadline:
            if locked.exists():
                return proc, release
            if proc.poll() is not None:
                self.fail("repo lock holder exited early with %s" % proc.returncode)
            time.sleep(0.02)
        proc.kill()
        self.fail("repo lock holder did not acquire lock")

    def test_teamsync_uses_ctf_home_and_publishes_v2_snapshot_with_artifacts(self):
        self.make_challenge("chal")
        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 0, result.stderr)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        snapshot = author_root / "snapshots" / current
        self.assertTrue((snapshot / ".rat" / "events" / "STATE.v2.jsonl").exists())
        self.assertTrue((snapshot / ".rat" / "objects" / "sha256").exists())
        self.assertFalse((self.team / "chals" / "chal" / "alice.jsonl").exists())

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("[alice] typed/direct", shown.stdout)
        self.assertIn("system = 0x50d70", shown.stdout)
        self.assertIn("[aggregate typed/direct offsets]", shown.stdout)

    def test_teamstate_reports_legacy_as_unverified_and_conflicts_nonzero(self):
        self.make_challenge("chal", "0x50d70")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        (self.team / ".author").write_text("bob\n", encoding="utf-8")
        self.make_challenge("chal", "0x60")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        legacy = self.team / "chals" / "chal" / "old.jsonl"
        legacy.write_text(json.dumps({"t": "offset", "k": "legacy", "v": "0x1"}) + "\n", encoding="utf-8")

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("CONFLICT system", shown.stdout)
        self.assertIn("[legacy/unverified]", shown.stdout)
        self.assertIn("old.jsonl", shown.stdout)

    def test_teamstate_rejects_forged_initial_primitive_pass(self):
        chal = self.ctf_home / "solve" / "chal"
        chal.mkdir(parents=True)
        stream = Stream(str(chal))
        stream.append("run.initialized", {"challenge": "chal"})
        for index in range(3):
            stream.append("observation.recorded", offset_doc(stream, "self_%d" % index, key="k%d" % index))
        events = stream.read()
        forged = {
            "schema": "rat.state-event/v2",
            "stream_id": events[-1]["stream_id"],
            "seq": events[-1]["seq"] + 1,
            "event_id": "evt_forged",
            "at": datetime.now(timezone.utc).isoformat(),
            "actor": "local",
            "task_id": "local",
            "type": "primitive.revised",
            "payload": {
                "primitive_id": "p",
                "status": "pass",
                "self_evidence": ["self_0", "self_1", "self_2"],
                "input_digest": DIGEST,
                "environment_digest": DIGEST,
            },
            "caused_by": [],
        }
        events.append(forged)
        event_path = chal / ".rat" / "events" / "STATE.v2.jsonl"
        with event_path.open("a", encoding="utf-8") as out:
            out.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
        self.make_snapshot_from_rat("chal", "alice", chal / ".rat", events)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("expected rat.primitive/v1", shown.stderr)
        self.assertNotIn("primitive[pass]", shown.stdout)

    def test_teamstate_rejects_immutable_snapshot_partial_tail(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        stream_path = author_root / "snapshots" / current / ".rat" / "events" / "STATE.v2.jsonl"
        with stream_path.open("ab") as out:
            out.write(b'{"partial":')

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("unterminated immutable snapshot event", shown.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamstate_rejects_current_symlink(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = author_root / "CURRENT"
        target = author_root / "CURRENT.target"
        target.write_text(current.read_text(encoding="utf-8"), encoding="utf-8")
        current.unlink()
        os.symlink(target, current)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("symlink", shown.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamsync_rejects_snapshot_symlink_publish_path(self):
        self.make_challenge("chal")
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        author_root.mkdir(parents=True)
        outside = self.root / "outside"
        outside.mkdir()
        os.symlink(outside, author_root / "snapshots")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamstate_rejects_state_root_stream_and_artifact_symlinks(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        state_root = self.team / "chals" / "chal" / "state-v2"
        saved = self.root / "saved-state-v2"
        state_root.rename(saved)
        os.symlink(saved, state_root)
        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("symlink", shown.stderr)
        state_root.unlink()
        saved.rename(state_root)

        author_root = state_root / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        snapshot = author_root / "snapshots" / current
        stream_path = snapshot / ".rat" / "events" / "STATE.v2.jsonl"
        saved_stream = snapshot / ".rat" / "events" / "STATE.v2.saved"
        stream_path.rename(saved_stream)
        os.symlink(saved_stream, stream_path)
        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("symlink", shown.stderr)
        stream_path.unlink()
        saved_stream.rename(stream_path)

        obj, _ = first_artifact_paths(snapshot / ".rat")
        # Stash the real object OUTSIDE the scanned tree: a .saved sibling left inside
        # objects/ would itself trip the unexpected-entry check, and which of the two
        # anomalies surfaces first depends on listdir order. Leaving only the symlink
        # makes the assertion deterministic.
        saved_obj = pathlib.Path(tempfile.mkdtemp()) / "obj"
        obj.rename(saved_obj)
        os.symlink(saved_obj, obj)
        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("symlink", shown.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamsync_rejects_source_event_symlink(self):
        chal = self.make_challenge("chal")
        stream_path = chal / ".rat" / "events" / "STATE.v2.jsonl"
        saved = chal / ".rat" / "events" / "STATE.v2.saved"
        stream_path.rename(saved)
        os.symlink(saved, stream_path)

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_teamsync_same_cursor_rejects_damaged_artifact_closure(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        metadata_files = sorted((author_root / "snapshots" / current / ".rat" / "metadata" / "sha256").glob("*/*.json"))
        self.assertTrue(metadata_files)
        metadata_files[0].unlink()

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("metadata closure mismatch", result.stderr)

    def test_teamstate_rejects_extra_and_dangling_snapshot_artifacts(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        snapshot_rat = author_root / "snapshots" / current / ".rat"
        extra = put_bytes(
            b"extra",
            kind="team-test",
            media_type="text/plain",
            logical_name="extra.txt",
            root=snapshot_rat,
            provenance={"evidence_policy": {"level": "direct", "promotion_allowed": True}},
        )["digest"]

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("object closure mismatch", shown.stderr)

        h = extra[7:]
        (snapshot_rat / "objects" / "sha256" / h[:2] / h[2:]).unlink()
        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("metadata closure mismatch", shown.stderr)

    def test_teamsync_rejects_same_stream_cursor_regression(self):
        chal = self.make_challenge("chal")
        event_path = chal / ".rat" / "events" / "STATE.v2.jsonl"
        first_line = event_path.read_text(encoding="utf-8").splitlines()[0] + "\n"
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        event_path.write_text(first_line, encoding="utf-8")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cursor regression", result.stderr)

    def test_teamsync_rejects_worktree_current_rollback_against_head(self):
        chal = self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        stream = Stream(str(chal))
        stream.append("note.recorded", {"note_id": "n1", "text": "advance"})
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        old_snapshot = sorted((author_root / "snapshots").iterdir())[0]
        shutil.rmtree(chal / ".rat")
        shutil.copytree(old_snapshot / ".rat", chal / ".rat")
        (author_root / "CURRENT").write_text(old_snapshot.name + "\n", encoding="utf-8")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cursor regression", result.stderr)

    def test_teamsync_rejects_rewrite_of_committed_snapshot_manifest(self):
        chal = self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        Stream(str(chal)).append("note.recorded", {"note_id": "n1", "text": "advance"})
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        self.mutate_publication(lambda doc: doc.__setitem__("replacement_reason", "tampered"))

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_teamsync_different_stream_lineage_requires_explicit_replace(self):
        self.make_challenge("chal", "0x50d70")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        old_current = (self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").read_text(encoding="utf-8").strip()
        self.make_challenge("chal", "0x60")

        rejected = self.run_tool("teamsync", "chal")
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("--replace-lineage", rejected.stderr)

        replaced = self.run_tool("teamsync", "--replace-lineage", "chal")
        self.assertEqual(replaced.returncode, 0, replaced.stderr)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        new_current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        publication = json.loads((author_root / "snapshots" / new_current / "PUBLICATION.json").read_text(encoding="utf-8"))
        self.assertEqual(publication["supersedes"]["snapshot"], old_current)
        self.assertEqual(publication["replacement_reason"], "explicit replace-lineage")
        self.assertFalse((author_root / "LINEAGE.jsonl").exists())

    def test_teamsync_commit_contains_current_snapshot_and_publication_manifest(self):
        self.make_challenge("chal")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 0, result.stderr)

        snapshot = self.latest_snapshot_relpath()
        paths = self.committed_paths()
        self.assertIn("chals/chal/state-v2/alice/CURRENT", paths)
        self.assertIn(snapshot + "/.rat/events/STATE.v2.jsonl", paths)
        self.assertIn(snapshot + "/PUBLICATION.json", paths)

    def test_teamsync_publication_and_commit_include_recursive_artifact_closure(self):
        self.make_challenge("chal")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 0, result.stderr)

        snapshot = self.latest_snapshot_relpath()
        publication = json.loads((self.team / snapshot / "PUBLICATION.json").read_text(encoding="utf-8"))
        events = store.parse_state_events((self.team / snapshot / ".rat" / "events" / "STATE.v2.jsonl").read_bytes(), allow_partial_tail=False)
        flat = set(store.collect_event_digests(events))
        published = set(publication["referenced_artifacts"])
        self.assertGreater(len(published), len(flat))
        self.assertTrue(flat < published)
        for digest in published:
            self.assert_committed_digest(snapshot, digest)

    def test_teamsync_rejects_malformed_nested_artifact_reference(self):
        chal = self.ctf_home / "solve" / "chal"
        chal.mkdir(parents=True)
        stream = Stream(str(chal))
        stream.append("run.initialized", {"challenge": "chal"})
        bad = {
            "schema": "rat.tool-result/v1",
            "tool": {"name": "gdbq", "version": "test", "build_digest": DIGEST},
            "run_id": "r", "invocation_id": "i", "status": "ok",
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:00:00+00:00",
            "duration_ms": 0, "inputs": [], "parameters": {},
            "summary": {}, "artifacts": [{"digest": "not-a-digest"}],
            "findings": [], "diagnostics": [],
            "exit": {"code": 0, "signal": None, "timed_out": False, "cancelled": False},
            "provenance": {"platform": {}, "dependency_versions": {}, "policy_digest": DIGEST, "cache": {}},
        }
        evidence = put_bytes(json.dumps(bad, sort_keys=True).encode(), kind="tool-result",
                             media_type="application/json", logical_name="bad-result.json",
                             root=stream.root)["digest"]
        stream.append("observation.recorded", {
            "observation_id": "bad_nested", "quality": {"level": "heuristic"},
            "validity": {"state": "active"}, "evidence": [evidence],
        })

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("malformed nested artifact digest", result.stderr)

    def test_teamsync_same_current_manifest_rejects_replacement_reason_without_supersedes(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        self.mutate_publication(lambda doc: (doc.__setitem__("replacement_reason", "explicit replace-lineage"), doc.__setitem__("supersedes", None)))

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_teamsync_same_current_manifest_rejects_supersedes_without_replacement_reason(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        self.mutate_publication(
            lambda doc: (doc.__setitem__("supersedes", {"stream_id": "legacy", "seq": 1, "snapshot": "legacy-1"}), doc.__setitem__("replacement_reason", None))
        )

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_teamsync_same_current_manifest_rejects_malformed_supersedes(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        self.mutate_publication(lambda doc: doc.__setitem__("supersedes", {"stream_id": "legacy"}))

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_teamsync_same_current_manifest_rejects_same_stream_replacement(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        current = (self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").read_text(encoding="utf-8").strip()
        stream_id, seq = current.rsplit("-", 1)
        self.mutate_publication(lambda doc: doc.update({
            "supersedes": {"stream_id": stream_id, "seq": int(seq) - 1, "snapshot": "%s-%d" % (stream_id, int(seq) - 1)},
            "replacement_reason": "explicit replace-lineage",
        }))

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_teamsync_same_current_manifest_rejects_future_normal_supersedes(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        current = (self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").read_text(encoding="utf-8").strip()
        stream_id, seq = current.rsplit("-", 1)
        self.mutate_publication(lambda doc: doc.update({
            "supersedes": {"stream_id": stream_id, "seq": int(seq) + 1, "snapshot": "%s-%d" % (stream_id, int(seq) + 1)},
            "replacement_reason": None,
        }))

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_teamstate_rejects_committed_future_normal_supersedes(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        current = (self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").read_text(encoding="utf-8").strip()
        stream_id, seq = current.rsplit("-", 1)
        path = self.mutate_publication(lambda doc: doc.update({
            "supersedes": {"stream_id": stream_id, "seq": int(seq) + 1, "snapshot": "%s-%d" % (stream_id, int(seq) + 1)},
            "replacement_reason": None,
        }))
        subprocess.run(["git", "add", "-f", str(path.relative_to(self.team))], cwd=self.team, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "forge lineage"], cwd=self.team, check=True)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("PUBLICATION", shown.stderr)

    def test_teamsync_refuses_uncommitted_manifestless_snapshot_as_compatibility(self):
        chal = self.make_challenge("chal")
        events = Stream(str(chal)).read()
        snapshot = self.make_snapshot_from_rat("chal", "alice", chal / ".rat", events)
        current = snapshot.parent.parent / "CURRENT"
        current.unlink()

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("compatibility", result.stderr)
        self.assertFalse(current.exists())

    def test_teamstate_and_teamsync_reject_nonexistent_manifest_predecessor(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        current = (self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").read_text(encoding="utf-8").strip()
        stream_id, _ = current.rsplit("-", 1)
        path = self.mutate_publication(lambda doc: doc.update({
            "supersedes": {"stream_id": stream_id, "seq": 1, "snapshot": "%s-1" % stream_id},
            "replacement_reason": None,
        }))
        subprocess.run(["git", "add", "-f", str(path.relative_to(self.team))], cwd=self.team, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "forge missing predecessor"], cwd=self.team, check=True)

        shown = self.run_tool("teamstate", "chal")
        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertEqual(retried.returncode, 2)
        self.assertIn("predecessor", shown.stderr)
        self.assertIn("predecessor", retried.stderr)

    def test_teamstate_and_teamsync_reject_non_immediate_committed_predecessor(self):
        chal = self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        Stream(str(chal)).append("note.recorded", {"note_id": "n1", "text": "three"})
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        Stream(str(chal)).append("note.recorded", {"note_id": "n2", "text": "four"})
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        first = sorted((author_root / "snapshots").iterdir())[0].name
        stream_id, seq = first.rsplit("-", 1)
        path = self.mutate_publication(lambda doc: doc.update({
            "supersedes": {"stream_id": stream_id, "seq": int(seq), "snapshot": first},
            "replacement_reason": None,
        }))
        subprocess.run(["git", "add", "-f", str(path.relative_to(self.team))], cwd=self.team, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "forge non-immediate predecessor"], cwd=self.team, check=True)

        shown = self.run_tool("teamstate", "chal")
        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertEqual(retried.returncode, 2)
        self.assertIn("committed predecessor", shown.stderr)
        self.assertIn("committed predecessor", retried.stderr)

    def test_teamsync_forces_ignored_rat_snapshot_closure_into_commit(self):
        self.commit_ignore_rat()
        self.make_challenge("chal")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath())

    def test_teamstate_rejects_snapshot_closure_missing_from_head_even_when_ignored(self):
        self.commit_ignore_rat()
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        snapshot = self.latest_snapshot_relpath()
        stream_rel = snapshot + "/.rat/events/STATE.v2.jsonl"
        if stream_rel in self.committed_paths():
            subprocess.run(["git", "rm", "-q", "-f", "--cached", "--", stream_rel], cwd=self.team, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "drop stream from committed tree"], cwd=self.team, check=True)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertRegex(shown.stderr, r"(HEAD|tracked|committed)")

    def test_teamsync_commit_retry_restages_existing_snapshot_current_and_manifest(self):
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"commit\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        first = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(first.returncode, 1)
        self.assertIn("git commit failed", first.stderr)

        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(retried.returncode, 0, retried.stderr)
        snapshot = self.latest_snapshot_relpath()
        paths = self.committed_paths()
        self.assertIn("chals/chal/state-v2/alice/CURRENT", paths)
        self.assertIn(snapshot + "/.rat/events/STATE.v2.jsonl", paths)
        self.assertIn(snapshot + "/PUBLICATION.json", paths)

    def test_teamsync_git_add_failure_retry_commits_complete_snapshot_closure(self):
        self.commit_ignore_rat()
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"add\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        first = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(first.returncode, 1)
        self.assertIn("git add failed", first.stderr)

        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath())

    def test_teamsync_git_diff_failure_retry_commits_complete_snapshot_closure(self):
        self.commit_ignore_rat()
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"diff\" ]; then exit 2; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        first = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(first.returncode, 1)
        self.assertIn("git diff failed", first.stderr)

        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath())

    def test_same_author_adversarial_publish_order_commits_selected_snapshot(self):
        chal = self.make_challenge("chal", "0x10")
        marker = self.root / "git-add-entered"
        release = self.root / "git-add-release"
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"add\" ]; then\n"
            "  touch \"%s\"\n"
            "  while [ ! -f \"%s\" ]; do sleep 0.02; done\n"
            "fi\n"
            "exec %s \"$@\"\n" % (marker, release, real_git)
        )

        first = subprocess.Popen([str(ROOT / "bin" / "teamsync"), "chal"], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + 5
        while time.time() < deadline and not marker.exists():
            if first.poll() is not None:
                stdout, stderr = first.communicate()
                self.fail("first teamsync exited before add barrier: %s%s" % (stdout, stderr))
            time.sleep(0.02)

        stream = Stream(str(chal))
        stream.append("observation.recorded", offset_doc(stream, "obs_seq3", value="0x20"))
        second = subprocess.Popen([str(ROOT / "bin" / "teamsync"), "chal"], env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaises(subprocess.TimeoutExpired):
            second.communicate(timeout=0.2)
        release.write_text("release\n", encoding="utf-8")
        first_stdout, first_stderr = first.communicate(timeout=5)
        second_stdout, second_stderr = second.communicate(timeout=5)

        self.assertEqual(first.returncode, 0, first_stderr + first_stdout)
        self.assertEqual(second.returncode, 0, second_stderr + second_stdout)
        current_rel = "chals/chal/state-v2/alice/CURRENT"
        committed_current = self.committed_text(current_rel).strip()
        self.assertTrue(committed_current.endswith("-3"))
        snapshot = "chals/chal/state-v2/alice/snapshots/%s" % committed_current
        paths = self.committed_paths()
        self.assertIn(snapshot + "/.rat/events/STATE.v2.jsonl", paths)
        self.assertIn(snapshot + "/PUBLICATION.json", paths)

    def test_cross_author_interleaving_commits_each_selected_snapshot(self):
        chal = self.make_challenge("chal", "0x10")
        marker = self.root / "alice-git-add-entered"
        release = self.root / "alice-git-add-release"
        real_git = shutil.which("git")
        alice_env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"add\" ]; then\n"
            "  touch \"%s\"\n"
            "  while [ ! -f \"%s\" ]; do sleep 0.02; done\n"
            "fi\n"
            "exec %s \"$@\"\n" % (marker, release, real_git)
        )

        alice = subprocess.Popen([str(ROOT / "bin" / "teamsync"), "chal"], env=alice_env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + 5
        while time.time() < deadline and not marker.exists():
            if alice.poll() is not None:
                stdout, stderr = alice.communicate()
                self.fail("alice teamsync exited before add barrier: %s%s" % (stdout, stderr))
            time.sleep(0.02)

        stream = Stream(str(chal))
        stream.append("observation.recorded", offset_doc(stream, "obs_bob", value="0x20"))
        (self.team / ".author").write_text("bob\n", encoding="utf-8")
        bob = subprocess.Popen([str(ROOT / "bin" / "teamsync"), "chal"], env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaises(subprocess.TimeoutExpired):
            bob.communicate(timeout=0.2)
        release.write_text("release\n", encoding="utf-8")
        alice_stdout, alice_stderr = alice.communicate(timeout=5)
        bob_stdout, bob_stderr = bob.communicate(timeout=5)

        self.assertEqual(alice.returncode, 0, alice_stderr + alice_stdout)
        self.assertEqual(bob.returncode, 0, bob_stderr + bob_stdout)
        self.assertTrue(self.committed_text("chals/chal/state-v2/alice/CURRENT").strip().endswith("-2"))
        self.assertTrue(self.committed_text("chals/chal/state-v2/bob/CURRENT").strip().endswith("-3"))
        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath(author="alice"))
        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath(author="bob"))

    def test_teamreg_stages_only_registration_paths(self):
        (self.team / "unrelated-local-note.txt").write_text("must not be registered\n", encoding="utf-8")

        result = self.run_tool("teamreg", "newchal")
        self.assertEqual(result.returncode, 0, result.stderr)

        paths = self.committed_paths()
        self.assertIn("chals/newchal/meta.json", paths)
        self.assertNotIn("unrelated-local-note.txt", paths)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamreg_refuses_meta_json_symlink_without_modifying_target(self):
        chal_dir = self.team / "chals" / "linkedchal"
        chal_dir.mkdir(parents=True)
        target = self.root / "target-meta.json"
        target.write_text("sentinel\n", encoding="utf-8")
        os.symlink(target, chal_dir / "meta.json")

        result = self.run_tool("teamreg", "linkedchal")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")

    def test_author_lock_requires_repository_lock(self):
        with self.assertRaisesRegex(RuntimeError, "author lock requires repository lock"):
            with store.author_lock(str(self.team), "chal", "alice"):
                pass
        with store.repo_lock(str(self.team)):
            with store.author_lock(str(self.team), "chal", "alice"):
                pass
            with self.assertRaisesRegex(RuntimeError, "repository lock must be acquired before author lock"):
                with store.author_lock(str(self.team), "chal", "alice"):
                    with store.repo_lock(str(self.team)):
                        pass

    def test_teamreg_waits_for_shared_repository_lock(self):
        proc, release = self.hold_repo_lock()
        try:
            running = subprocess.Popen([str(ROOT / "bin" / "teamreg"), "lockedchal"], env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.assertRaises(subprocess.TimeoutExpired):
                running.communicate(timeout=0.2)
            self.assertFalse((self.team / "chals" / "lockedchal" / "meta.json").exists())
            release.write_text("release\n", encoding="utf-8")
            stdout, stderr = running.communicate(timeout=5)
            self.assertEqual(running.returncode, 0, stderr)
            self.assertIn("registered", stdout)
        finally:
            release.write_text("release\n", encoding="utf-8")
            proc.wait(timeout=5)

    def test_teamstate_waits_for_shared_repository_lock_before_aggregate(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        proc, release = self.hold_repo_lock()
        try:
            running = subprocess.Popen([str(ROOT / "bin" / "teamstate"), "chal"], env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.assertRaises(subprocess.TimeoutExpired):
                running.communicate(timeout=0.2)
            release.write_text("release\n", encoding="utf-8")
            stdout, stderr = running.communicate(timeout=5)
            self.assertEqual(running.returncode, 0, stderr)
            self.assertIn("[aggregate typed/direct offsets]", stdout)
        finally:
            release.write_text("release\n", encoding="utf-8")
            proc.wait(timeout=5)

    def test_teamsync_rejects_corrupt_source_without_partial_current(self):
        chal = self.make_challenge("chal")
        _, meta = first_artifact_paths(chal / ".rat")
        meta.write_text("{not json", encoding="utf-8")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("metadata", result.stderr)
        self.assertFalse((self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").exists())
        self.assertFalse((self.team / "chals" / "chal" / "state-v2" / "alice" / "snapshots").exists())

    def test_teamsync_git_pull_failure_is_local_only_nonzero(self):
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"remote\" ]; then echo origin; exit 0; fi\n"
            "if [ \"$3\" = \"pull\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        result = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(result.returncode, 1)
        self.assertIn("git pull failed", result.stderr)
        self.assertTrue((self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").exists())

    def test_teamsync_git_pull_failure_retry_commits_complete_snapshot_closure(self):
        self.commit_ignore_rat()
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"remote\" ]; then echo origin; exit 0; fi\n"
            "if [ \"$3\" = \"pull\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        first = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(first.returncode, 1)
        self.assertIn("git pull failed", first.stderr)

        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath())

    def test_teamsync_git_add_failure_is_local_only_nonzero(self):
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"add\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        result = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(result.returncode, 1)
        self.assertIn("git add failed", result.stderr)
        self.assertTrue((self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").exists())

    def test_teamsync_git_diff_failure_is_local_only_nonzero(self):
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"diff\" ]; then exit 2; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        result = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(result.returncode, 1)
        self.assertIn("git diff failed", result.stderr)
        self.assertTrue((self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").exists())

    def test_teamsync_git_push_failure_is_local_only_nonzero(self):
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"remote\" ]; then echo origin; exit 0; fi\n"
            "if [ \"$3\" = \"pull\" ]; then exit 0; fi\n"
            "if [ \"$3\" = \"push\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        result = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(result.returncode, 1)
        self.assertIn("git push failed", result.stderr)
        self.assertTrue((self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").exists())

    def test_teamsync_git_push_failure_retry_commits_complete_snapshot_closure(self):
        self.commit_ignore_rat()
        self.make_challenge("chal")
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"remote\" ]; then echo origin; exit 0; fi\n"
            "if [ \"$3\" = \"pull\" ]; then exit 0; fi\n"
            "if [ \"$3\" = \"push\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        first = self.run_tool_with_env(env, "teamsync", "chal")
        self.assertEqual(first.returncode, 1)
        self.assertIn("git push failed", first.stderr)

        retried = self.run_tool("teamsync", "chal")
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assert_committed_snapshot_closure(self.latest_snapshot_relpath())

    def test_teamsync_unmerged_repository_state_is_conflict_without_snapshot_mutation(self):
        (self.team / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "add", "base.txt"], cwd=self.team, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=self.team, check=True)
        subprocess.run(["git", "switch", "-q", "-c", "side"], cwd=self.team, check=True)
        (self.team / "base.txt").write_text("side\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "side", "-q"], cwd=self.team, check=True)
        subprocess.run(["git", "switch", "-q", "main"], cwd=self.team, check=True)
        (self.team / "base.txt").write_text("main\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-am", "main", "-q"], cwd=self.team, check=True)
        merge = subprocess.run(["git", "merge", "side"], cwd=self.team, text=True, capture_output=True)
        self.assertNotEqual(merge.returncode, 0)
        self.make_challenge("chal")

        result = self.run_tool("teamsync", "chal")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflict", result.stderr.lower())
        self.assertFalse((self.team / "chals" / "chal" / "state-v2" / "alice" / "CURRENT").exists())

    def test_teamreg_conflict_returns_nonzero_without_registration_claim(self):
        git_dir = subprocess.run(
            ["git", "rev-parse", "--git-dir"], cwd=self.team, text=True, capture_output=True, check=True
        ).stdout.strip()
        (self.team / git_dir / "MERGE_HEAD").write_text("deadbeef\n", encoding="utf-8")

        result = self.run_tool("teamreg", "blocked")
        self.assertEqual(result.returncode, 1)
        self.assertIn("conflict", result.stderr.lower())
        self.assertNotIn("registered", result.stdout)
        self.assertFalse((self.team / "chals" / "blocked" / "meta.json").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamsync_refuses_symlinked_staging_root(self):
        self.make_challenge("chal")
        outside = self.root / "outside-staging"
        outside.mkdir()
        os.symlink(outside, self.team / ".git" / "teamsync-staging")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_teamstate_git_pull_failure_suppresses_aggregate(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        real_git = shutil.which("git")
        env = self.fake_git_env(
            "#!/bin/sh\n"
            "if [ \"$3\" = \"remote\" ]; then echo origin; exit 0; fi\n"
            "if [ \"$3\" = \"pull\" ]; then exit 1; fi\n"
            "exec %s \"$@\"\n" % real_git
        )

        shown = self.run_tool_with_env(env, "teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("local-stale", shown.stderr)
        self.assertNotIn("[aggregate typed/direct offsets]", shown.stdout)

    def test_teamstate_remote_without_upstream_suppresses_aggregate(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        remote = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=self.team, check=True)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("local-stale", shown.stderr)
        self.assertNotIn("[aggregate typed/direct offsets]", shown.stdout)

    def test_teamstate_dirty_selected_publication_suppresses_aggregate(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = author_root / "CURRENT"
        current.write_text(current.read_text(encoding="utf-8") + "\n", encoding="utf-8")

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("local-only", shown.stderr)
        self.assertNotIn("[aggregate typed/direct offsets]", shown.stdout)

    def test_snapshot_metadata_json_values_must_be_objects(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        snapshot_rat = author_root / "snapshots" / current / ".rat"
        events = store.parse_state_events(
            (snapshot_rat / "events" / "STATE.v2.jsonl").read_bytes(),
            allow_partial_tail=False,
        )
        digests = store.collect_event_digests(events)
        metadata_file = next((snapshot_rat / "metadata" / "sha256").glob("*/*.json"))

        for malformed in ("[]", "null", '"string"'):
            with self.subTest(metadata=malformed):
                metadata_file.write_text(malformed, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "metadata"):
                    store.verify_artifact_closure(snapshot_rat, digests, containment_root=self.team, label="snapshot", exact=True)

    def test_existing_snapshot_publication_manifest_must_validate_on_retry(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        publication = author_root / "snapshots" / current / "PUBLICATION.json"
        doc = json.loads(publication.read_text(encoding="utf-8"))
        doc["snapshot"] = "forged"
        publication.write_text(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_manifestless_legacy_snapshot_is_accepted_as_compatibility(self):
        chal = self.make_challenge("chal")
        events = Stream(str(chal)).read()
        self.make_snapshot_from_rat("chal", "alice", chal / ".rat", events)
        subprocess.run(["git", "add", "-f", "chals/chal"], cwd=self.team, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "legacy snapshot"], cwd=self.team, check=True)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("compatibility", shown.stdout)
        self.assertIn("system = 0x50d70", shown.stdout)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamsync_rejects_dangling_publication_symlink_instead_of_compatibility(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        publication = self.publication_path()
        publication.unlink()
        os.symlink(self.root / "missing-publication.json", publication)

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)
        self.assertNotIn("compatibility", result.stdout)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_teamstate_rejects_dangling_publication_symlink_instead_of_compatibility(self):
        self.make_challenge("chal")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        publication = self.publication_path()
        publication.unlink()
        os.symlink(self.root / "missing-publication.json", publication)

        shown = self.run_tool("teamstate", "chal")
        self.assertEqual(shown.returncode, 2)
        self.assertIn("symlink", shown.stderr)
        self.assertNotIn("compatibility snapshot", shown.stdout)

    def test_replace_lineage_existing_snapshot_still_requires_publication_manifest(self):
        self.make_challenge("chal", "0x50d70")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        self.make_challenge("chal", "0x60")
        chal = self.ctf_home / "solve" / "chal"
        events = Stream(str(chal)).read()
        new_current = "%s-%d" % (events[-1]["stream_id"], events[-1]["seq"])
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        shutil.copytree(chal / ".rat", author_root / "snapshots" / new_current / ".rat")

        result = self.run_tool("teamsync", "--replace-lineage", "chal")
        self.assertEqual(result.returncode, 2)
        self.assertIn("PUBLICATION", result.stderr)

    def test_pointer_swap_failure_keeps_old_current_and_no_lineage_claim(self):
        self.make_challenge("chal", "0x50d70")
        self.assertEqual(self.run_tool("teamsync", "chal").returncode, 0)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        old_current = (author_root / "CURRENT").read_text(encoding="utf-8")
        self.make_challenge("chal", "0x60")
        author_root.chmod(0o500)
        try:
            result = self.run_tool("teamsync", "--replace-lineage", "chal")
        finally:
            author_root.chmod(0o700)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((author_root / "CURRENT").read_text(encoding="utf-8"), old_current)
        self.assertFalse((author_root / "LINEAGE.jsonl").exists())

    def test_checkpoint_overflow_artifact_is_published_in_snapshot_closure(self):
        chal = self.make_challenge("chal")
        stream = Stream(str(chal))
        for index in range(40):
            stream.append("note.recorded", {"note_id": "n%d" % index, "text": "x" * 200})
        checkpoint = stream.checkpoint(phase="P1", task_id="t", role="r", reason="small", max_bytes=128)
        self.assertIn("overflow_artifact", checkpoint)

        result = self.run_tool("teamsync", "chal")
        self.assertEqual(result.returncode, 0, result.stderr)
        author_root = self.team / "chals" / "chal" / "state-v2" / "alice"
        current = (author_root / "CURRENT").read_text(encoding="utf-8").strip()
        snapshot_rat = author_root / "snapshots" / current / ".rat"
        self.assertTrue(artifact_exists(snapshot_rat, checkpoint["context_artifact"]))
        self.assertTrue(artifact_exists(snapshot_rat, checkpoint["overflow_artifact"]))

    def test_trailing_newline_slugs_are_rejected(self):
        self.make_challenge("chal")
        synced = self.run_tool("teamsync", "chal\n")
        shown = self.run_tool("teamstate", "chal\n")
        self.assertEqual(synced.returncode, 2)
        self.assertEqual(shown.returncode, 2)
        self.assertIn("unsafe challenge", synced.stderr)
        self.assertIn("usage: teamstate", shown.stderr)


class TeamRebaseRecovery(unittest.TestCase):
    """A failed pull --rebase must not leave the shared repo wedged for every author."""

    @staticmethod
    def _git(cwd, *args):
        return subprocess.run(
            ["git", "-c", "user.email=t@x", "-c", "user.name=t", *args],
            cwd=cwd, capture_output=True, text=True)

    def test_abort_in_progress_rebase_clears_conflict_wedge(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "f.txt")
            self._git(d, "init", "-q")
            with open(f, "w") as fh:
                fh.write("base\n")
            self._git(d, "add", "-A"); self._git(d, "commit", "-q", "-m", "base")
            base_branch = self._git(d, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
            self._git(d, "checkout", "-q", "-b", "feature")
            with open(f, "w") as fh:
                fh.write("feature side\n")
            self._git(d, "add", "-A"); self._git(d, "commit", "-q", "-m", "feature")
            self._git(d, "checkout", "-q", base_branch)
            with open(f, "w") as fh:
                fh.write("mainline side\n")
            self._git(d, "add", "-A"); self._git(d, "commit", "-q", "-m", "mainline")
            # Conflicting rebase leaves .git/rebase-merge behind, exactly what a failed
            # `pull --rebase` produces.
            self._git(d, "rebase", "feature")
            self.assertIsNotNone(store.conflict_state(d), "precondition: repo is wedged")

            self.assertTrue(store.abort_in_progress_rebase(d))
            # Wedge cleared: conflict_state is clean and no rebase state remains.
            self.assertIsNone(store.conflict_state(d))
            self.assertFalse(os.path.exists(os.path.join(d, ".git", "rebase-merge")))
            self.assertFalse(os.path.exists(os.path.join(d, ".git", "rebase-apply")))
            # Idempotent: a no-op when nothing is in progress.
            self.assertFalse(store.abort_in_progress_rebase(d))


if __name__ == "__main__":
    unittest.main()
