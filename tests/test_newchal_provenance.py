"""newchal keeps route JSON and source artifact provenance across pwninit."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NewchalProvenanceTests(unittest.TestCase):
    def _run(self, pwninit_rc):
        with tempfile.TemporaryDirectory(prefix="newchal-provenance-") as folder:
            root = Path(folder)
            home = root / "home"
            bindir = home / "bin"
            bindir.mkdir(parents=True)
            (bindir / "ratlib").symlink_to(ROOT / "bin/ratlib", target_is_directory=True)
            shutil.copy2(ROOT / "bin/newchal", bindir / "newchal")
            template = home / "solve/_template"
            template.mkdir(parents=True)
            (template / "state.md").write_text("# fixture\n")
            route_doc = {"schema": "rat.route-result/v2", "signals": [],
                         "dimensions": {key: [] for key in ("vulnerability_surfaces", "program_shapes",
                                                        "obstacles", "constraints")},
                         "unresolved": [], "next": [], "capabilities": {}, "leads": [],
                         "decision": None, "commitment": "unknown", "skill": None,
                         "diagnostics": []}
            for name, body in (
                ("ctfguard", "exit 0"),
                ("libcgate", "exit 0"),
                ("rat", "echo '" + json.dumps(route_doc, separators=(",", ":")) + "'\n"
                        "echo 'diagnostic on stderr' >&2\nexit 0"),
            ):
                path = bindir / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o755)
            pwninit = root / "pwninit"
            pwninit.write_text("#!/bin/sh\nprintf X >> libc.so.6\n"
                               + ("cp chall chall_patched\n" if pwninit_rc == 0 else "")
                               + "exit %d\n" % pwninit_rc)
            pwninit.chmod(0o755)
            binary = root / "chall"
            shutil.copy2("/bin/true", binary)
            libc = root / "provided-libc.so"
            libc.write_bytes(b"provided libc fixture")
            original_binary = binary.read_bytes()
            original_libc = libc.read_bytes()
            env = os.environ | {"CTF_HOME": str(home),
                                "PATH": str(root) + os.pathsep + os.environ["PATH"]}
            for attempt in range(2):
                run = subprocess.run([str(bindir / "newchal"), "fixture", str(binary), str(libc)],
                                     env=env, capture_output=True, text=True, timeout=60)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                solve = home / "solve/fixture"
                route = json.loads((solve / ".scaffold/route.json").read_text())
                self.assertEqual(route["schema"], "rat.route-result/v2")
                self.assertIn("diagnostic on stderr", (solve / ".scaffold/route.stderr.log").read_text())
                self.assertNotIn("ROUTE UNKNOWN", (solve / "state.md").read_text())
                self.assertEqual((solve / "original/chall").read_bytes(), original_binary)
                self.assertEqual((solve / "original/libc.so.6").read_bytes(), original_libc)
                manifest = json.loads((solve / "run.json").read_text())
                provenance = manifest["artifact_provenance"]
                self.assertEqual(provenance["binary"]["original"]["sha256"],
                                 "sha256:" + hashlib.sha256(original_binary).hexdigest())
                self.assertEqual(provenance["libc"]["original"]["sha256"],
                                 "sha256:" + hashlib.sha256(original_libc).hexdigest())
                self.assertEqual(provenance["libc"]["working"]["sha256"],
                                 "sha256:" + hashlib.sha256(original_libc + b"X").hexdigest())
                self.assertEqual(provenance["transformation"]["status"],
                                 "success" if pwninit_rc == 0 else "failed")
                self.assertEqual(provenance["transformation"]["exit_code"], pwninit_rc)
                self.assertEqual(provenance["execution"]["binary"]["path"],
                                 "chall_patched" if pwninit_rc == 0 else "chall")
                self.assertEqual((solve / "original/libc.so.6").read_bytes(), original_libc)

    def test_success_preserves_originals_and_route_json(self):
        self._run(0)

    def test_failed_pwninit_preserves_originals_and_uses_base_binary(self):
        self._run(9)

    def test_route_output_names_preserve_main_and_additional_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="newchal-route-names-") as folder:
            root = Path(folder)
            home = root / "home"
            bindir = home / "bin"
            bindir.mkdir(parents=True)
            (bindir / "ratlib").symlink_to(ROOT / "bin/ratlib", target_is_directory=True)
            shutil.copy2(ROOT / "bin/newchal", bindir / "newchal")
            template = home / "solve/_template"
            template.mkdir(parents=True)
            (template / "state.md").write_text("# fixture\n")
            route_doc = {"schema": "rat.route-result/v2", "signals": [],
                         "dimensions": {key: [] for key in ("vulnerability_surfaces", "program_shapes",
                                                        "obstacles", "constraints")},
                         "unresolved": [], "next": [], "capabilities": {}, "leads": [],
                         "decision": None, "commitment": "unknown", "skill": None,
                         "diagnostics": []}
            for name, body in (("ctfguard", "exit 0"), ("libcgate", "exit 0"),
                               ("rat", "echo '" + json.dumps(route_doc) + "'\n"
                                "echo 'route diagnostic' >&2")):
                tool = bindir / name
                tool.write_text("#!/bin/sh\n" + body + "\n")
                tool.chmod(0o755)
            env = os.environ | {"CTF_HOME": str(home)}
            for artifact_name in ("route.json", "route.stderr.log"):
                for role in ("main", "extra"):
                    case = (role + "_" + artifact_name).replace(".", "_")
                    binary = root / (artifact_name if role == "main" else "chall")
                    shutil.copy2("/bin/true", binary)
                    payload = binary.read_bytes()
                    args = [str(bindir / "newchal"), case, str(binary)]
                    extra_payload = b"additional artifact with route output name"
                    if role == "extra":
                        extra = root / artifact_name
                        extra.write_bytes(extra_payload)
                        args += ["--artifact", "extra=" + str(extra)]
                    run = subprocess.run(args, env=env, capture_output=True,
                                         text=True, timeout=60)
                    self.assertEqual(run.returncode, 0, (case, run.stdout, run.stderr))
                    solve = home / "solve" / case
                    manifest = json.loads((solve / "run.json").read_text())
                    self.assertEqual((solve / binary.name).read_bytes(), payload)
                    self.assertEqual((solve / "original" / binary.name).read_bytes(), payload)
                    expected_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
                    self.assertEqual(manifest["artifact_provenance"]["binary"]["original"]["sha256"],
                                     expected_digest)
                    self.assertEqual(manifest["artifact_provenance"]["binary"]["working"]["sha256"],
                                     expected_digest)
                    if role == "extra":
                        self.assertEqual((solve / artifact_name).read_bytes(), extra_payload)
                        extra_input = next(item for item in manifest["inputs"]
                                           if item["name"] == artifact_name)
                        self.assertEqual(extra_input["sha256"],
                                         "sha256:" + hashlib.sha256(extra_payload).hexdigest())
                    self.assertEqual(json.loads((solve / ".scaffold/route.json").read_text()),
                                     route_doc)
                    self.assertIn("route diagnostic",
                                  (solve / ".scaffold/route.stderr.log").read_text())


if __name__ == "__main__":
    unittest.main()
