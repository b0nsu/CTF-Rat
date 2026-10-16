"""Raw-code loading and multi-artifact ingestion regressions (#101 / #103)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin"
sys.path.insert(0, str(BIN))
from ratlib.raw_loader import inspect_raw, load_spec, project
from ratlib.route import route
from ratlib.run_manifest import materialize_for_solve, read


def boot_sector(path):
    payload = bytearray(10660)  # intentionally not sector aligned
    payload[510:512] = b"\x55\xaa"
    Path(path).write_bytes(payload)


class RawAndMultiArtifactTests(unittest.TestCase):
    def test_boot_disk_and_unknown_hints(self):
        with tempfile.TemporaryDirectory() as root:
            boot = Path(root) / "drive0"
            boot_sector(boot)
            identity = inspect_raw(boot)
            self.assertEqual(identity["kind"], "boot-sector-candidate")
            self.assertFalse(identity["sector_aligned"])
            disk = Path(root) / "drive1"
            disk.write_bytes(bytes(1474560))
            self.assertEqual(inspect_raw(disk)["kind"], "disk-image-candidate")
            other = Path(root) / "unknown"
            other.write_bytes(bytes(1024))
            self.assertEqual(inspect_raw(other)["kind"], "unknown")
            elf = Path(root) / "elf"
            elf.write_bytes(b"\x7fELF" + bytes(1000))
            self.assertEqual(inspect_raw(elf)["kind"], "unknown")

    def test_load_spec_requires_all_hints_and_valid_entry(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "blob"
            binary.write_bytes(b"\x90" * 16)
            self.assertIsNone(load_spec(binary))
            spec = load_spec(binary, arch="i386", base="0x1000", entry="0x1003")
            self.assertEqual(spec, {"backend": "blob", "arch": "X86",
                                    "base_addr": 4096, "entry_point": 4099})
            for kwargs in ({"arch": "i386"}, {"arch": "i386", "base": "0x1000"},
                           {"arch": "mystery", "base": "0x1000", "entry": "0x1000"},
                           {"arch": "i386", "base": "0x1000", "entry": "0x1010"},
                           {"arch": "i386", "base": "-1", "entry": "0"}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    load_spec(binary, **kwargs)

    def test_raw_route_exposes_next_prerequisite_without_commitment(self):
        profile = {"artifact_identity": {"kind": "boot-sector-candidate", "size": 10660}}
        doc = route(profile=profile)
        self.assertEqual(doc["commitment"], "provisional")
        self.assertIsNone(doc["skill"])
        self.assertIn("raw-artifact", doc["leads"])
        self.assertTrue(any(a["query"] == "rat route" for a in doc["next"]))
        profile["blob_load_spec"] = {"backend": "blob", "arch": "X86",
                                     "base_addr": 4096, "entry_point": 4096}
        doc = route(profile=profile)
        self.assertTrue(any(x["kind"] == "operator-blob-map" for x in doc["signals"]))

    def test_project_blob_opts_are_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "stage"
            binary.write_bytes(bytes([0x90]) * 16)
            calls = []
            class FakeAngr:
                @staticmethod
                def Project(*args, **kwargs):
                    calls.append((args, kwargs))
                    return object()
            class FakeArchinfo:
                @staticmethod
                def arch_from_id(value):
                    return "archinfo:" + value
            with mock.patch.dict(sys.modules, {"angr": FakeAngr, "archinfo": FakeArchinfo}):
                project(str(binary), None)
                project(str(binary), load_spec(binary, arch="i386", base="0x1000", entry="0x1000"))
            self.assertNotIn("main_opts", calls[0][1])
            self.assertEqual(calls[1][1]["main_opts"]["arch"], "archinfo:X86")
            self.assertEqual(calls[1][1]["main_opts"]["base_addr"], 4096)

    def test_rat_route_raw_file_returns_next_loader_prerequisite(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / "drive0"
            boot_sector(binary)
            result = subprocess.run([str(BIN / "rat"), "route", str(binary), "--fast",
                                     "--format", "json"], capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            doc = json.loads(result.stdout)
            self.assertIn("raw-artifact", doc["leads"])
            self.assertEqual(doc["commitment"], "provisional")
            self.assertTrue(any("arch" in x["target"] for x in doc["next"]))

    def test_manifest_multi_inputs_qemu_hints_and_idempotence(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            binary = root / "drive0"
            disk = root / "drive1"
            runner = root / "run.sh"
            manifest = root / "run.json"
            marker = root / "DO_NOT_EXECUTE"
            boot_sector(binary)
            disk.write_bytes(bytes(1024))
            runner.write_text("#!/bin/sh\nqemu-system-i386 -cpu qemu32,+rdrand -fda drive0 -fdb drive1\n" +
                              "touch " + str(marker) + "\n")
            args = dict(name="test", binary=str(binary), libc=None, remote=None,
                        owner_path="solve/test/run.json",
                        extra_inputs=[("image", str(disk)), ("runner", str(runner))])
            materialize_for_solve(None, str(manifest), **args)
            doc = read(str(manifest))
            self.assertEqual(len(doc["inputs"]), 3)
            self.assertEqual({i["role"] for i in doc["inputs"]}, {"binary", "image", "runner"})
            for item in doc["inputs"]:
                self.assertEqual(len(item["sha256"].split(":", 1)[1]), 64)
            hints = doc["environment"]["qemu_launch_hints"]
            self.assertIn("-cpu qemu32,+rdrand", hints[0]["commands"][0]["line"])
            self.assertFalse(marker.exists(), "runner must never execute")
            materialize_for_solve(None, str(manifest), **args)
            self.assertEqual(len(read(str(manifest))["inputs"]), 3)
            with self.assertRaises(ValueError):
                materialize_for_solve(None, str(manifest), **(args | {
                    "extra_inputs": [("image", str(disk)), ("image", str(disk))]}))

    def test_newchal_boot_multi_image_scaffolding_and_duplicate_guard(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            kit = root / "kit"
            (kit / "bin").mkdir(parents=True)
            (kit / "solve/_template").mkdir(parents=True)
            (kit / "solve/_template/state.md").write_text("# {{NAME}} {{BIN}}\n")
            for name, script in (("ctfguard", "exit 0"), ("libcgate", "exit 0"),
                                 ("recon", "echo UNEXPECTED_ELF_RECON; exit 23")):
                path = kit / "bin" / name
                path.write_text("#!/bin/sh\n" + script + "\n")
                path.chmod(0o755)
            source = root / "source"
            source.mkdir()
            boot = source / "drive0"
            disk = source / "drive1"
            runner = source / "run.sh"
            boot_sector(boot)
            disk.write_bytes(bytes(1474560))
            runner.write_text("#!/bin/sh\nqemu-system-i386 -cpu qemu32,+rdrand -fda drive0\n")
            env = dict(os.environ, CTF_HOME=str(kit))
            cmd = [str(BIN / "newchal"), "bumpy", str(boot),
                   "--artifact", "image=" + str(disk),
                   "--artifact", "runner=" + str(runner)]
            result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("UNEXPECTED_ELF_RECON", result.stdout)
            target = kit / "solve/bumpy"
            self.assertTrue((target / "drive1").is_file())
            self.assertTrue((target / "run.sh").is_file())
            manifest = read(str(target / "run.json"))
            self.assertEqual(len(manifest["inputs"]), 3)
            self.assertEqual(manifest["inputs"][1]["sha256"],
                             "sha256:" + hashlib.sha256(disk.read_bytes()).hexdigest())
            duplicate = subprocess.run(cmd + ["--artifact", "extra=" + str(disk)],
                                       env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(duplicate.returncode, 2)
            self.assertIn("colliding artifact filename", duplicate.stderr)


if __name__ == "__main__":
    unittest.main()
