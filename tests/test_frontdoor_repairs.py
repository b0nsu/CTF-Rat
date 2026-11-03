"""Front-door digest, next-command, and Ghidra availability regressions."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))
from ratlib.cards import project_pwn_capability
from ratlib.decomp_cache import write_meta
from ratlib.route import route
from ratlib.route_feedback import load_feedback


def load_cli(name):
    path = str(ROOT / "bin" / name)
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class FrontdoorRepairTests(unittest.TestCase):
    def test_pwn_card_reads_and_validates_canonical_profile_digest(self):
        profile = {"schema": "rat.binary-profile/v1", "binary_digest": "sha256:" + "a" * 64,
                   "imports": ["gets"], "facts": []}
        self.assertEqual(project_pwn_capability(profile)["provenance"]["binary_sha256"],
                         profile["binary_digest"])
        profile["binary_digest"] = "sha256:wrong"
        self.assertIsNone(project_pwn_capability(profile)["provenance"]["binary_sha256"])

    def test_string_next_is_one_line_and_function_next_is_executable(self):
        rat = load_cli("rat")
        self.assertEqual(rat._render_next("decomp ./chall 0x401234"),
                         ["  decomp ./chall 0x401234"])
        revq = load_cli("revq")
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "chall"
            shutil.copy2("/bin/true", binary)
            raw = bytearray(binary.read_bytes())
            raw[16:18] = (3).to_bytes(2, "little")  # ET_DYN, stripped PIE address convention
            binary.write_bytes(raw)
            ghidra = Path(folder) / "ghidra"
            (ghidra / "Ghidra").mkdir(parents=True)
            (ghidra / "support").mkdir()
            analyzer = ghidra / "support/analyzeHeadless"
            analyzer.write_text("#!/bin/sh\nexit 99\n")
            analyzer.chmod(0o755)
            (ghidra / "Ghidra/application.properties").write_text("application.version=fake\n")
            cache = Path(str(binary) + ".decomp")
            cache.mkdir()
            (cache / "_index.txt").write_text("00101234\tFUN_00101234\t8\t00101234_FUN_00101234\n")
            (cache / "00101234_FUN_00101234.c").write_text("int FUN_00101234(void) { return 9; }\n")
            (cache / ".rat-decomp-status.json").write_text(json.dumps({
                "image_base": "100000", "discovered": 1, "exported": 1, "failed": []}))
            write_meta(str(cache), str(binary), str(ghidra),
                       str(ROOT / "bin/ghidra_scripts"), "complete")
            rev = {"bin": str(binary), "sha256": hashlib.sha256(raw).hexdigest(),
                   "engine": "angr", "schema": "rat.revmap/v1", "functions": [
                       {"name": "main", "addr": 0x401234, "size": 8, "calls": [],
                        "strings": [], "call_sites": [], "nblocks": 1, "ninstr": 2}],
                   "imports": [], "strings": []}
            card = revq.compute_function_card(rev, "main")
            self.assertIsInstance(card["next"], list)
            command = card["next"][0]
            self.assertEqual(command["query"], "decomp")
            self.assertIn("0x401234", command["target"])
            rendered = rat._render_next(card["next"])
            self.assertEqual(len(rendered), 1)
            env = os.environ | {"CTF_HOME": str(ROOT), "GHIDRA_HOME": str(ghidra)}
            result = subprocess.run([str(ROOT / "bin/decomp"), *shlex.split(command["target"])],
                                    env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("return 9", result.stdout)

    def test_doctor_and_decomp_resolve_ghidra_home_without_path_entry(self):
        with tempfile.TemporaryDirectory() as folder:
            ghidra = Path(folder) / "ghidra"
            (ghidra / "support").mkdir(parents=True)
            analyzer = ghidra / "support/analyzeHeadless"
            analyzer.write_text("#!/bin/sh\necho fake-ghidra\n")
            analyzer.chmod(0o755)
            env = os.environ | {"CTF_HOME": str(ROOT), "GHIDRA_HOME": str(ghidra)}
            doctor = subprocess.run([str(ROOT / "bin/rat-doctor"), "/bin/true", "--format", "json"],
                                    env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(doctor.returncode, 0, doctor.stderr)
            report = json.loads(doctor.stdout)["summary"]
            self.assertEqual(report["capabilities"]["ghidra"]["status"], "available")
            self.assertEqual(report["capabilities"]["ghidra"]["path"], str(analyzer))
            self.assertEqual(report["routes"]["ghidra"]["status"], "available")

    @unittest.skipUnless(shutil.which("gcc"), "gcc required for real profile")
    def test_real_profile_pwn_card_feedback_is_digest_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, binary = root / "chall.c", root / "chall"
            source.write_text('#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){char b[8]={0};if(c>1)strcpy(b,v[1]);puts(b);}\n')
            subprocess.run(["gcc", "-no-pie", "-o", str(binary), str(source)],
                           check=True, capture_output=True)
            digest = "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest()
            rat = load_cli("rat")
            profile = rat._gather_profile(str(binary), str(root / ".rat"))
            self.assertEqual(profile["binary_digest"], digest)
            card = subprocess.run([str(ROOT / "bin/rat"), "query", "pwn", str(binary),
                                   "--format", "json"], capture_output=True, text=True, timeout=30)
            self.assertEqual(card.returncode, 0, card.stderr)
            doc = json.loads(card.stdout)
            self.assertEqual(doc["provenance"]["binary_sha256"], digest)
            self.assertFalse(any(item["code"] == "stale_cache" for item in doc["diagnostics"]))
            actions = route(profile=profile, binary_digest=digest)["next"]
            pwn_actions = [action for action in actions if action["query"] == "rat query pwn"]
            self.assertTrue(pwn_actions)
            feedback = load_feedback(str(root), digest, pwn_actions)
            self.assertTrue(feedback)
            self.assertTrue(all(item["status"] != "stale" for item in feedback.values()))


if __name__ == "__main__":
    unittest.main()
